/**
 * Saker, local net (layer 2) stats for bsd
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
#include <sys/sysctl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <netdb.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <net/if_types.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>
#include <poll.h>
#include <errno.h>

#define SAKER_INT unsigned long long

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
map<string, SAKER_INT> src;

// same for dst addresses
map<string, SAKER_INT> dst;

// container that keeps pairs (MAC, count)
// representing src addresses of packets
// ordered by count of packets (or count of bytes)
multimap<SAKER_INT, string> src_score;

// same for dst addresses
multimap<SAKER_INT, string> dst_score;

// keeps list of own macs (for -r/-l handling)
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
bool g_promisc = true; // on by dafault!
bool g_mac_cnt = false;
bool g_pkt_cnt = false;
bool g_resolve_arp = false;
bool g_resolve_ip = false;

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
#define DEFAULT_DELAY (10)

SAKER_INT pkt_cnt = DEFAULT_PKT_CNT;
SAKER_INT mac_cnt = 0;

int time_delay = DEFAULT_DELAY;

SAKER_INT pkt_grb = 0; // number of packets actually grabbed
SAKER_INT size_grb = 0;

time_t time_start = 0;

char *bpf;
struct bpf_program bpff;

// PCAP callback function, grabs the packet
void h(u_char * useless, const struct pcap_pkthdr * pkthdr, const u_char * pkt)
{
    char buf[50];
    int  i;
    bpf_u_int32 pkt_size = pkthdr->len;

    map<string, SAKER_INT>::iterator mit;

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

//    if (g_debug)
//        cout << s1 << " ->> " << s2 << endl;
}


// resolver stuff

typedef map<string, string> resolvermap;
resolvermap resolver;

static char *resolveip(char *ipstr)
{
    struct in_addr ip;
    inet_aton(ipstr, &ip);

    struct hostent *hp = gethostbyaddr((const char *)&ip, sizeof ip, AF_INET);

    if (hp)
    {
        // trim hostname
        char * p = strchr(hp->h_name, '.');
        if (p != NULL) *p = '\0';
        return hp->h_name;
    }

    return ipstr;
}

#define ROUNDUP(a) \
        ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

int prepare_arp()
{
    int mib[6];
    size_t needed;
    char *lim, *buf, *next;

    mib[0] = CTL_NET;
    mib[1] = PF_ROUTE;
    mib[2] = 0;
    mib[3] = AF_INET;
    mib[4] = NET_RT_FLAGS;
    mib[5] = RTF_LLINFO;

    /* Retrieve routing table */

    if(sysctl(mib, 6, NULL, &needed, NULL, 0) < 0)
    {
        perror("Error: route-sysctl-estimate failed");
        exit(1);
    }

    if((buf = (char *)malloc(needed)) == NULL)
    {
        perror("Error: malloc failed");
        exit(1);
    }

    if(sysctl(mib, 6, buf, &needed, NULL, 0) < 0)
    {
        perror("Error: retrieval of routing table failed");
        exit(1);
    }

    lim = buf + needed;

    struct rt_msghdr *rtm = NULL;
    for (next = buf; next < lim; next += rtm->rtm_msglen)
    {
        rtm = (struct rt_msghdr *)next;
        struct sockaddr_inarp *sinarp = (struct sockaddr_inarp *)(rtm + 1);
        struct sockaddr_dl *sdl = (struct sockaddr_dl *)((char *)sinarp + ROUNDUP(sinarp->sin_len));

        if (
            sdl->sdl_alen
            && (sdl->sdl_type == IFT_ETHER || sdl->sdl_type == IFT_L2VLAN)
            && sdl->sdl_alen == ETHER_ADDR_LEN
            )
        {
            char *thismac = ether_ntoa((struct ether_addr *)LLADDR(sdl));

            resolvermap::iterator hit = resolver.find(string(thismac));   // check if already in the cache
            if (hit != resolver.end())
                continue;

            char *thisip = inet_ntoa(sinarp->sin_addr);

            char *thishost = NULL;
            if (g_resolve_ip)
                thishost = resolveip(thisip);
            else
                thishost = thisip;

            // save to cache
            if (g_debug)
                cout << "MAC: " << string(thismac) << " -> " << string(thishost) << endl;

            resolver.insert(make_pair(string(thismac), string(thishost)));
        }

    }

    free(buf);
    return(0);
}

string resolvemac(string mac)
{
    resolvermap::iterator hit;

    if (g_debug)
           cout << "Resolve MAC: " << mac << endl;

    string h;
    hit = resolver.find(mac);   // find in the cache
    if (hit == resolver.end()) // not found, rebuild cache
    {
        prepare_arp();
        hit = resolver.find(mac);

        if (hit == resolver.end()) // still not found
            return mac;
    }

    if (g_debug)
           cout << "Resolve MAC (done): " << hit->first << endl;

    return hit->second;
}


template<class T> class uncount
{
    SAKER_INT* cnt_var;
public:
    uncount(SAKER_INT* cv) : cnt_var(cv) {}
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
    SAKER_INT _cnt;
    SAKER_INT _mac_cnt;
//    bool g_mac_cnt;
public:
    print(ostream &out, SAKER_INT pc, SAKER_INT mc) : os(out), _cnt(pc), _mac_cnt(mc)
    {
/*        if (mc != DEFAULT_MAC_CNT)
            g_mac_cnt = true;
        else
            g_mac_cnt = false; */
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
//cerr << "((" << g_mac_cnt << ":" << _mac_cnt << ":" << (_mac_cnt==0) << "))" << endl;

        if (g_mac_cnt && _mac_cnt==0)
            return;

        _mac_cnt--;

        char f[1024];
        char f1[1024];
        human_size(x.first, f1);
        if (g_bytemode)
        {
            sprintf(f, "%10sB", f1);
        }
        else
        {
            sprintf(f, "%10sPkt", f1);
        }

        os <<  f << " ";

        if (g_percent)
        {
            char s[10];
            sprintf(s, " %4.1f ", (static_cast<double>(x.first)/_cnt)*100.0);
            cout << s << "%";
        }

        if (g_mark)
        {
            if (ownmacs.find(x.second) != ownmacs.end())
                cout << " * ";
            else
                cout << "   ";
        }


        if (g_resolve_arp) // resolve_ip is checked inside
            cout << resolvemac(x.second);
        else
            cout << x.second;

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

// Converts a size to a human readable format.
void human_size(SAKER_INT _size, char *output)
{
    static const SAKER_INT KB = 1024;
    static const SAKER_INT MB = 1024 * KB;
    static const SAKER_INT GB = 1024 * MB;

    SAKER_INT number = 0, reminder = 0;
    SAKER_INT size = _size;
    if (size < KB)
    {
        sprintf(output, "%llu  ", size);
    }
    else
    {
        if (size < MB)
        {
            number = size / KB;
            reminder = (size * 100 / KB) % 100;

            snprintf(output, 256, "%llu.%02llu K", number, reminder);
        }
        else
        {
            if (size < GB)
            {
                number = size / MB;
                reminder = (size * 100 / MB) % 100;
                sprintf(output, "%llu.%02llu M", number, reminder);
            }
            else
            {
                if (size >= GB)
                {
                    number = size / GB;
                    reminder = (size * 100 / GB) % 100;
                    sprintf(output, "%llu.%02llu G", number, reminder);
                }
            }
        }
    }

// cerr << "!" << size << "!" << number << "!" << output << "!" << endl;
//  strNumber.Replace(".00", "");
}

void report(void)
{
// container that keeps pairs (MAC, count)
// representing src addresses of packets
// ordered by count of packets
    multimap<int, string> src_score;

// same for dst addresses
    multimap<int, string> dst_score;

    // count the packets-per-second
    SAKER_INT delta =  time(NULL) - time_start;
    SAKER_INT pps = pkt_grb / (delta ? delta : 1);
    SAKER_INT bps = size_grb / (delta ? delta : 1);

    char hbps[1024];
    char hbbps[1024];
    char hsize[1024];
    char hpkt[1024];
    char hpps[1024];
    human_size(bps, hbps);
    human_size(bps*8, hbbps);
    human_size(size_grb, hsize);
    human_size(pkt_grb, hpkt);
    human_size(pps, hpps);

    cout << endl;
    cout << "Interfaces: ";
     for (int i=0; i<pcap_dev_no; i++)
        cout << dv[i].device << " ";
    cout << endl;

    cout << "Total packets: " << hpkt << "Pkt (" << hpps << "Pkts/s)" << endl;
    cout << "Total size: " << hsize << "B (" << hbps << "B/s, " << hbbps << "Bits/s)" << endl;
//    cout << "Macs: " << mac_cnt << endl;
    if (!g_only_dst)
    {
        cout << "SRC stats:" << endl;
        SAKER_INT srcv = g_bytemode ? size_grb : pkt_grb;

        // we have first to copy all stats from src, which is ordered by MAC to src_score
        // which is ordered by count, making possible printing stats ordered by count
        transform(src.begin(), src.end(), inserter(src_score, src_score.begin()), revert<string, SAKER_INT>());

        if (g_remote)
            for_each(src_score.begin(), src_score.end(), uncount<pair<SAKER_INT, string> >(&srcv));

        // and now we simply print stats by count :)
        if (g_ascend)
            for_each(src_score.begin(), src_score.end(), print<pair<SAKER_INT, string> >(cout, srcv, mac_cnt));
        else
            for_each(src_score.rbegin(), src_score.rend(), print<pair<SAKER_INT, string> >(cout, srcv, mac_cnt));
    }

    if (!g_only_src)
    {
        cout << "DST stats:" << endl;
        SAKER_INT dstv = g_bytemode ? size_grb : pkt_grb;

        // same for dst
        transform(dst.begin(), dst.end(), inserter(dst_score, dst_score.begin()), revert<string, SAKER_INT>());

        if (g_remote)
            for_each(dst_score.begin(), dst_score.end(), uncount<pair<SAKER_INT, string> >(&dstv));

        if (g_ascend)
            for_each(dst_score.begin(), dst_score.end(), print<pair<SAKER_INT, string> >(cout, dstv, mac_cnt));
        else
            for_each(dst_score.rbegin(), dst_score.rend(), print<pair<SAKER_INT, string> >(cout, dstv, mac_cnt));
    }
}

void sig_handler(int sig)
{
    cerr << endl << "saker: shutdown" << endl;
    exit(127);
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

    while ((opt = getopt (argc, argv, "i:n:m:t:clapbhvorsdxXf:VD")) != -1)
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
            g_pkt_cnt = true;
            break;

        case 'm':
            mac_cnt = atoi(optarg);
            g_mac_cnt = true;
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

        case 'o':
            g_promisc = false;
            break;

        case 'x':
            g_resolve_arp = true;
            break;

        case 'X':
            g_resolve_arp = true;
            g_resolve_ip = true;
            break;

        case 'c':
             g_cont = true;
            pkt_cnt=0;
            g_pkt_cnt = false;
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
            << "  -i <if>   network interface (many interfaces can be specified)" << endl
            << "  -h        show this info" << endl
            << "  -n num    number of packets to capture (default " << DEFAULT_PKT_CNT << ", -1 for unlimited)" << endl
            << "  -a        ascending sort (default descending)" << endl
            << "  -m num    number of MACs to display in summary (all by default)" << endl
            << "  -p        show percentage" << endl
            << "  -b        count bytes (instead of packets)" << endl
            << "  -r        count only remote ends (exclude own MACs)" << endl
            << "  -l        mark local MACs with asterisk (see also -r)" << endl
            << "  -s        show only source stats" << endl
            << "  -d        show only destination stats" << endl
            << "  -x        resolve MACs to IPs" << endl
            << "  -X        resolve IPs to hostnames (implies -x)" << endl
            << "  -c        continuous mode" << endl
            << "  -o        turn off promiscuous mode" << endl
            << "  -t num    time delay for continuous mode in seconds (default "<< DEFAULT_DELAY << ")" << endl
            << "  -f 'expr' expr is a pcap-style BPF expression (man tcpdump)" << endl
            << "  -v        be verbose (e.g. output each packet)" << endl
            << "  -V        print version and exit" << endl
            << "  -D        enable debug output (you are not supposed to understand it)" << endl;
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

            dv[i].pcap = pcap_open_live(dv[i].device, 100, g_promisc ? 1 : 0, 1000, errbuff);
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
    SAKER_INT poll_delay = time_delay*1000;
    while (g_cont || pkt_grb < pkt_cnt)
    {
        int dispatched;
        int pollret;
        switch (pollret = poll(pollfdtab, pcap_dev_no, poll_delay))
        {
            case -1:
                if (errno != EINTR)
                    perror("Error: poll failed");
                break;

            case 0:
                break;

            default:
//                cerr << "POLL(" << pollret << ")" << endl;

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
