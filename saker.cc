/**
 * Saker, net stats for bsd
 * written by Jan Pustelnik, Marcin Gryszkalis
 * no license, grab the code and run.
 *
 * Requires FreeBSD 4.6 or later (because of poll(2) behavior on BPF devs)
 *
 * Compile with
 * $ c++ -o saker -lpcap saker.cc
 *
 * $Id$
 */

// system and C includes
#include <pcap.h>
#include <cstdio>

#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <net/if_dl.h>
#include <signal.h>
#include <time.h>
#include <poll.h>
#include <errno.h>

// C++ includes
#include <string>
#include <iostream>
#include <set>
#include <map>
#include <algorithm>
#include <iterator>

using namespace std;

// container that keeps pairs (MAC, count) representing src
// addresses of packets ordered by MAC adress
map<string, long> src;

// same for dst addresses
map<string, long> dst;

// container that keeps pairs (MAC, count)
// representing src addresses of packets
// ordered by count of packets (or count of bytes)
multimap<long, string> src_score;

// same for dst addresses
multimap<long, string> dst_score;

// keeps list of own macs (for -r handling)
set<string> ownmacs;

bool g_verbose = false;
bool g_remote = false;
bool g_bytemode = false;
bool g_mark = false;
bool g_debug = false;
bool g_ascend = false;
bool g_percent = false;
bool g_only_dst = false;
bool g_only_src = false;
bool g_cont = false;
bool g_bpf = false;


struct saker_device
{
    char *device;
    pcap_t *pcap;
    pollfd pfd;
};

#define MAX_IFACES (16)
saker_device dv[MAX_IFACES];
pollfd pollfdtab[MAX_IFACES];
int    pcap_dev_no = 0;

#define PCAP_MAX_PKT_PER_DISPATCH (256)

#define DEFAULT_PKT_CNT (100)
#define DEFAULT_MAC_CNT (-1)
#define DEFAULT_DELAY (10)

long pkt_cnt = DEFAULT_PKT_CNT;
long mac_cnt = DEFAULT_MAC_CNT;
int time_delay = DEFAULT_DELAY;
long pkt_grb = 0; // number of packets actually grabbed
long size_grb = 0;

time_t time_start = 0;

char *bpf;
struct bpf_program bpff;

// PCAP callback function, grabs the packet
void
h(u_char * useless, const struct pcap_pkthdr * pkthdr, const u_char * pkt)
{
    char buf[50];
    int  i;
	bpf_u_int32 pkt_size = pkthdr->len;

    map<string, long>::iterator mit;

    pkt_grb++;
	size_grb += pkt_size;

    for (i = 0; i < 6; i++)
        sprintf(buf+3*i, "%02x:", pkt[i + 6]);
    buf[17] = '\0';

    string s1(buf);
    mit=src.find(s1);   // find element of src having MAC equal to s1
    if (mit == src.end()) // not found, create
	{
		if (g_bytemode)
        	src.insert(make_pair(s1, pkt_size));
		else
	       src.insert(make_pair(s1, 1));
	}
    else // found, increase count
	{
		if (g_bytemode)
			mit->second += pkt_size;
		else
        	++(mit -> second);
	}

    for (i = 0; i < 6; i++)
        sprintf(buf+3*i, "%02x:", pkt[i]);
    buf[17] = '\0';

    string s2(buf);
    mit=dst.find(s2);   // same for dst
    if (mit == dst.end())
	{
    		if (g_bytemode)
        	dst.insert(make_pair(s2, pkt_size));
		else
	       dst.insert(make_pair(s2, 1));

	}
    else
 	{
		if (g_bytemode)
			mit->second += pkt_size;
		else
        	++(mit -> second);
	}

    if (g_debug)
        cout << s1 << " ->> " << s2 << endl;
}

template<class T> class uncount
{
    long* cnt_var;
public:
    uncount(long* cv) : cnt_var(cv) {}
    void operator() (T x)
    {
        if (ownmacs.find(x.second) != ownmacs.end())
        {
            *cnt_var = *cnt_var - x.first;
            if (g_debug)
                cout << "DEBUG uncount: " << x.first << " " << *cnt_var << endl;
        }
    }
};

// utility for printing pairs to output stream
template<class T> class print
{
    ostream &os;
    long _pkt_cnt;
    long _mac_cnt;
    bool g_mac_cnt;
public:
    print(ostream &out, long pc, long mc) : os(out), _pkt_cnt(pc), _mac_cnt(mc) {
        if (mc != DEFAULT_MAC_CNT)
            g_mac_cnt = true;
        else
            g_mac_cnt = false;
    }

    void operator() (T x)
    {
        if (g_remote)
        {
            if (ownmacs.find(x.second) != ownmacs.end())
            {
                if (g_debug)
                    cout << "DEBUG: erased: " << x.second << endl;
                return;
            }
        }
        if (g_mac_cnt) {
                _mac_cnt--;
                if (_mac_cnt < 0)
                        return; // shouldn't be asserted?
        }

    char f[80];
    sprintf(f, "%12d", x.first);
        os << "\t" << f << "\t" << x.second;

        if (g_percent)
        {
            char s[10];
            sprintf(s, "%4.1f", (static_cast<double>(x.first)/_pkt_cnt)*100.0);
            cout << "\t" << s << "%";
        }

        if (g_mark)
        {
            if (ownmacs.find(x.second) != ownmacs.end())
                cout << " *";
        }

        cout << endl;
    }
};

// utility for reverting pairs
template <class T, class S> class revert
{
// input:  pair (A, B)
// output: pair (B, A)
public:
    revert() {}
    pair<S, T> operator() (pair<T, S> x)
    {
        return make_pair(x.second, x.first);
    }
};

void report(void)
{
// container that keeps pairs (MAC, count)
// representing src addresses of packets
// ordered by count of packets
    multimap<int, string> src_score;

// same for dst addresses
    multimap<int, string> dst_score;

    // count the packets-per-second
    long delta =  time(NULL) - time_start;
    long pps = pkt_grb / (delta ? delta : 1);
    long bps = size_grb / (delta ? delta : 1);

    char hbps[1024];
    char hsize[1024];
    human_size(bps, hbps);
    human_size(size_grb, hsize);

    cout << endl;
    cout << "Interfaces: ";
     for (int i=0; i<pcap_dev_no; i++)
        cout << dv[i].device << " ";
    cout << endl;

    cout << "Total packets: " << pkt_grb << " (" << pps << " pkts/s)" << endl;
    cout << "Total size: " << hsize << " (" << hbps << " bps)" << endl;

    if (!g_only_dst)
    {
        cout << "SRC stats:" << endl;
        long srcv = g_bytemode ? size_grb : pkt_grb;

        // we have first to copy all stats from src, which is ordered by MAC to src_score
        // which is ordered by count, making possible printing stats ordered by count
        transform(src.begin(), src.end(), inserter(src_score, src_score.begin()), revert<string, long>());

        if (g_remote)
            for_each(src_score.begin(), src_score.end(), uncount<pair<long, string> >(&srcv));

        // and now we simply print stats by count :)
        if (g_ascend)
            for_each(src_score.begin(), src_score.end(), print<pair<long, string> >(cout, srcv, mac_cnt));
        else
            for_each(src_score.rbegin(), src_score.rend(), print<pair<long, string> >(cout, srcv, mac_cnt));
    }

    if (!g_only_src)
    {
        cout << "DST stats:" << endl;
        long dstv = g_bytemode ? size_grb : pkt_grb;

        // same for dst
        transform(dst.begin(), dst.end(), inserter(dst_score, dst_score.begin()), revert<string, long>());

        if (g_remote)
            for_each(dst_score.begin(), dst_score.end(), uncount<pair<long, string> >(&dstv));

        if (g_ascend)
            for_each(dst_score.begin(), dst_score.end(), print<pair<long, string> >(cout, dstv, mac_cnt));
        else
            for_each(dst_score.rbegin(), dst_score.rend(), print<pair<long, string> >(cout, dstv, mac_cnt));
    }
}

void sig_handler(int sig)
{
    cerr << endl << "saker: shutdown" << endl;
    exit(127);
}

// Converts a size to a human readable format.
void human_size(long size, char *output)
{
    static const long KB = 1024;
    static const long MB = 1024 * KB;
    static const long GB = 1024 * MB;

    long number, reminder;

    if (size < KB)
    {
        sprintf(output, "%ld B", size);
    }
    else
    {
        if (size < MB)
        {
            number = size / KB;
            reminder = (size * 100 / KB) % 100;

            sprintf(output, "%ld.%02ld KB", size, reminder);
        }
        else
        {
            if (size < GB)
            {
                number = size / MB;
                reminder = (size * 100 / MB) % 100;
                sprintf(output, "%ld.%02ld MB", number, reminder);
            }
            else
            {
                if (size >= GB)
                {
                    number = size / GB;
                    reminder = (size * 100 / GB) % 100;
                    sprintf(output, "%ld.%02ld GB", number, reminder);
                }
            }
        }
    }

//  strNumber.Replace(".00", "");
}

int main(int argc, char *argv[])
{
    bpf_u_int32     net, mask;
    int             opt;
    bool            usage = false; // show usage
    char            errbuff[PCAP_ERRBUF_SIZE];
    int             i;

    char rev[255] = "$Revision$";
    rev[strlen(rev)-2] = '\0';
    char *revp = rev + 11; // skip prefix
    cerr << "saker v" << revp << endl;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    for (i=0; i<MAX_IFACES; i++)
    {
        dv[i].pcap = NULL;
        dv[i].device = NULL;
        dv[i].pfd.fd = -1;
    }

    while ((opt = getopt (argc, argv, "i:n:m:t:clapbhvrsdf:VD")) != -1)
    {
        switch (opt)
        {
        case 'i':
            if (pcap_dev_no < MAX_IFACES)
            {
                dv[pcap_dev_no++].device = (char *) strdup(optarg);
            }
            else
            {
                cerr << "Error: too many interfaces specified" << endl;
                exit(2);
            }
            break;

        case 'n':
            pkt_cnt = atoi(optarg);
            break;

        case 'm':
            mac_cnt = atoi(optarg);
            break;

        case 't':
            time_delay = atoi(optarg);
            if (time_delay < 1)
                time_delay = 1;
            break;

        case 'a':
            g_ascend = true;
            break;

        case 'p':
            g_percent = true;
            break;

        case 'b':
            g_bytemode = true;
            break;

        case 'h':
            usage = true;
            break;

        case 'v':
            g_verbose = true;
            break;

        case 'r':
            g_remote = true;
            break;

        case 'l':
            g_mark = true;
            break;

        case 'c':
         {g_cont = true; pkt_cnt=-1;}
            break;

        case 'd':
            g_only_dst = true;
            if (g_only_src)
            {
                cerr << "Error: You cannot have both -d and -s." << endl;
                usage = true;
            }
            break;

        case 's':
            g_only_src = true;
            if (g_only_dst)
            {
                cerr << "Error: You cannot have both -d and -s." << endl;
                usage = true;
            }
            break;

        case 'f':
            g_bpf = true;
            bpf = (char *) strdup(optarg);
            break;

        case 'V':
            exit(0);
            break;

        case 'D':
            g_debug = true;
            break;

        case '?':
        default:
            cerr << "Error: Unknown command line option." << endl;
            usage = true;
            break;
        }
    }

    if (usage == false && pcap_dev_no == 0)
    {
        cerr << "Error: Interface(s) not specified." << endl;
        usage = true;
    }

    if (usage)
    {
        cerr << endl
            << "Usage: saker [-apbrmvhVD] [-n num] [-m num] [-s|-d] [-c -t num] [-f 'expr'] -i <if> [-i <if2> ... ]" << endl
            << "\t-i <if>\t\tnetwork interface (many interfaces can be specified)" << endl
            << "\t-h\t\tshow this info" << endl
            << "\t-n num\t\tnumber of packets to capture (default " << DEFAULT_PKT_CNT << ", -1 for unlimited)" << endl
            << "\t-a\t\tascending sort (default descending)" << endl
            << "\t-m num\t\tnumber of MACs to display in summary (all by default)" << endl
            << "\t-p\t\tshow percentage" << endl
            << "\t-b\t\tcount bytes (instead of packets)" << endl
            << "\t-r\t\tcount only remote ends (exclude own MACs)" << endl
            << "\t-l\t\tmark local MACs with asterisk (see also -r)" << endl
            << "\t-s\t\tshow only source stats" << endl
            << "\t-d\t\tshow only destination stats" << endl
            << "\t-c\t\tcontinuous mode" << endl
            << "\t-t\t\ttime delay for continuous mode in seconds (default "<< DEFAULT_DELAY << ")" << endl
            << "\t-f 'expr'\t\texpr is a pcap-style BPF expression (man tcpdump)" << endl
            << "\t-v\t\tbe verbose (e.g. output each packet)" << endl
            << "\t-V\t\tprint version and exit" << endl
            << "\t-D\t\tenable debug output (you are not supposed to understand it)" << endl;
        exit(1);
    }

    cerr << "Listening on: ";
    for (i=0; i<pcap_dev_no; i++)
        cerr << dv[i].device << " ";
    cerr << endl;

    // get own mac's

    struct ifaddrs *ifap, *ifaphead;
    int rtnerr;
    const struct sockaddr_dl *sdl;
    caddr_t ap;
    int alen;
    char ownmac[18] = "..:..:..:..:..:.."; // 6*2+5+1

    rtnerr = getifaddrs(&ifaphead);
    if (rtnerr)
    {
        perror("Error: getifaddrs failed: ");
        exit(2);
    }

    if (g_verbose)
        cout << "Own MAC adresses:" << endl;
    for (ifap = ifaphead; ifap; ifap = ifap->ifa_next)
    {
        if (ifap->ifa_addr->sa_family == AF_LINK)
        {
            sdl = (const struct sockaddr_dl *) ifap->ifa_addr;
            ap = ((caddr_t)((sdl)->sdl_data + (sdl)->sdl_nlen));
            alen = sdl->sdl_alen;
            if (ap && alen > 0)
            {
                int i;
                for (i = 0; i < alen; i++, ap++)
                {
                    if (i > 0)
                        sprintf(ownmac+2+(i-1)*3,"%c%02x", ':' , 0xff&*ap);
                    else
                        sprintf(ownmac+i*3,"%02x", 0xff&*ap);
                }

                if (g_verbose)
                    cout << ownmac
                        << " (" << ifap->ifa_name << ")"
                        << endl;

                string ownmacstr(ownmac);
                ownmacs.insert(ownmacstr);
            }
        }
    }


    if (g_debug)
        copy(ownmacs.begin(), ownmacs.end(), ostream_iterator<string>(cout, "!\n"));

    freeifaddrs(ifaphead);

    time_start = time(NULL);

    //initialize pcap
    for (i=0; i<pcap_dev_no; i++)
    {
        if (g_debug)
            cerr << "PCAP init for " << dv[i].device << endl;

            int pcap_net = pcap_lookupnet(dv[i].device, &net, &mask, errbuff);
            if (pcap_net == -1)
            {
                cerr << "Error: pcap_lookupnet failed: "
                    << errbuff
                    << endl;
                exit(4);
            }

            dv[i].pcap = pcap_open_live(dv[i].device, 100, 1, 1000, errbuff);
            if (dv[i].pcap == NULL)
            {
                cerr << "Error: cannot open pcap live: "
                    << errbuff
                    << endl;
                exit(3);
            }

            if (pcap_setnonblock(dv[i].pcap, 1, errbuff) < 0)
            {
                cerr << "Error: cannot set nonblocking mode: "
                    << errbuff
                    << endl;
                exit(3);
            }

            if (g_bpf)
            {
                    if (pcap_compile(dv[i].pcap, &bpff, bpf, 1, 0) < 0)
                    {
                        cerr << "Error: cannot compile BPF filter expression ("
                            << pcap_geterr(dv[i].pcap)
                            << ")"
                            << endl;
                        exit(6);
                    }

                    if (pcap_setfilter(dv[i].pcap, &bpff))
                    {
                        cerr << "Error: cannot install BPF filter ("
                            << pcap_geterr(dv[i].pcap)
                            << ")"
                            << endl;
                        exit(5);
                    }
            }
    }

    // init for poll(2)
    for (i=0; i<pcap_dev_no; i++)
    {
        if ((dv[i].pfd.fd = pcap_get_selectable_fd(dv[i].pcap)) == -1)
        {
            perror("Error: pcap_get_selectable_fd failed");
            exit(5);
        }

		if (g_debug)
			cerr << "pcap_selectable_fd: " << dv[i].device << "=" << dv[i].pfd.fd << endl;

        dv[i].pfd.events = POLLRDNORM;
		pollfdtab[i] = dv[i].pfd;
    }

    // the main loop
    time_t last_report_time = time(NULL);
	long poll_delay = time_delay*1000;
    while (g_cont || pkt_grb < pkt_cnt)
    {
        int dispatched;
		int pollret;
        switch (pollret = poll(pollfdtab, pcap_dev_no, poll_delay))
        {
            case -1:
                if (errno != EINTR)
                    perror("poll");
                break;

            case 0:
                break;

            default:
//				cerr << "POLL(" << pollret << ")" << endl;

                for (i=0; i<pcap_dev_no; i++)
                {
                    if (pollfdtab[i].revents)
                    {
                        if (dispatched = pcap_dispatch(dv[i].pcap, PCAP_MAX_PKT_PER_DISPATCH, h, NULL) < 0)
                        {
                            cerr << "Error: error during pcap dispatch ("
                                << pcap_geterr(dv[i].pcap)
                                << ")"
                                << endl;
                            exit(5);
                        }
                    }
                }
        }

        time_t now = time(NULL);
        if (now - last_report_time >= time_delay)
        {
            report();
            last_report_time = now;
        }

    }

    report();

    return 0;
}


