// $Id$

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
map<string, int> src;

// same for dst addresses
map<string, int> dst;

// container that keeps pairs (MAC, count)
// representing src addresses of packets
// ordered by count of packets
multimap<int, string> src_score;

// same for dst addresses
multimap<int, string> dst_score;

// keeps list of own macs (for -r handling)
set<string> ownmacs;

bool g_verbose = false;
bool g_remote = false;
bool g_mark = false;
bool g_debug = false;
bool g_ascend = false;
bool g_percent = false;
bool g_only_dst = false;
bool g_only_src = false;
bool g_cont = false;

#define DEFAULT_PKT_CNT (100)
#define DEFAULT_MAC_CNT (-1)
#define DEFAULT_DELAY (10)

int pkt_cnt = DEFAULT_PKT_CNT;
int mac_cnt = DEFAULT_MAC_CNT;
int time_delay = DEFAULT_DELAY;
int src_cnt;
int dst_cnt;
int pkt_grb = 0; // number of packets actually grabbed
int time_start = 0;

void
h(u_char * useless, const struct pcap_pkthdr * pkthdr, const u_char * pkt)
{
    char buf[50];
    int  i;
    map<string, int>::iterator mit;

    pkt_grb++;
    
    for (i = 0; i < 6; i++)
        sprintf(buf+3*i, "%02x:", pkt[i]);
    buf[17] = '\0';

    string s1(buf);
    mit=src.find(s1);   // find element of src having MAC equal to s1
    if (mit == src.end()) // not found, create
        src.insert(make_pair(s1, 1));
    else // found, increase count by 1
        ++(mit -> second);

    for (i = 0; i < 6; i++)
        sprintf(buf+3*i, "%02x:", pkt[i + 6]);
    buf[17] = '\0';

    string s2(buf);
    mit=dst.find(s2);   // same for dst
    if (mit == dst.end())
        dst.insert(make_pair(s2, 1));
    else
        ++(mit -> second);

    if (g_verbose)
        cout << s1 << " ->> " << s2 << endl;
}

template<class T> class uncount
{
    int* cnt_var;
public:
    uncount(int* cv) : cnt_var(cv) {}
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
    int _pkt_cnt;
    int _mac_cnt;
    bool g_mac_cnt;
public:
    print(ostream &out, int pc, int mc) : os(out), _pkt_cnt(pc), _mac_cnt(mc) { 
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

        os << "\t" << x.first << "\t" << x.second;

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
    
    cout << endl;
    cout << "Total packets: " << pkt_grb << " (" << pps << " pkts/s)" << endl;

    if (!g_only_dst)
    {
		cout << "SRC stats:" << endl;
		src_cnt = pkt_grb;

		// we have first to copy all stats from src, which is ordered by MAC to src_score
		// which is ordered by count, making possible printing stats ordered by count
		transform(src.begin(), src.end(), inserter(src_score, src_score.begin()), revert<string, int>());

		if (g_remote)
			for_each(src_score.begin(), src_score.end(), uncount<pair<int, string> >(&src_cnt));

		// and now we simply print stats by count :)
		if (g_ascend)
			for_each(src_score.begin(), src_score.end(), print<pair<int, string> >(cout, src_cnt, mac_cnt));
		else
			for_each(src_score.rbegin(), src_score.rend(), print<pair<int, string> >(cout, src_cnt, mac_cnt));
    }

    if (!g_only_src)
    {
		cout << "DST stats:" << endl;
		dst_cnt = pkt_grb;

		// same for dst
		transform(dst.begin(), dst.end(), inserter(dst_score, dst_score.begin()), revert<string, int>());

		if (g_remote)
			for_each(dst_score.begin(), dst_score.end(), uncount<pair<int, string> >(&dst_cnt));
		
		if (g_ascend)
			for_each(dst_score.begin(), dst_score.end(), print<pair<int, string> >(cout, dst_cnt, mac_cnt));
		else
			for_each(dst_score.rbegin(), dst_score.rend(), print<pair<int, string> >(cout, dst_cnt, mac_cnt));
    }
}

void alarm_report(int sig)
{
	report();
	alarm(time_delay);
}

void sig_handler(int sig)
{
	cerr << endl << "saker: shutdown" << endl;
	exit(127);	
}

int
main(int argc, char *argv[])
{
    char           *pcap_dev = NULL;
    bpf_u_int32     net, mask;
    char            errbuff[1024];
    int             opt;
    bool            usage = false; // show usage

    time_start = time(NULL);

    char rev[255] = "$Revision$";
    rev[strlen(rev)-2] = '\0';
    char *revp = rev + 11; // skip prefix
    cerr << "saker v" << revp << endl;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    while ((opt = getopt (argc, argv, "i:n:m:t:claphvrsdVD")) != -1)
    {
        switch (opt)
        {
        case 'i':
            pcap_dev = (char *) strdup (optarg);
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
            g_cont = true;
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

    if (usage == false && pcap_dev == NULL)
    {
        cerr << "Error: Interface not specified." << endl;
        usage = true;
    }

    if (usage)
    {
        cerr << endl 
			<< "Usage: saker [-aprmvhVD] [-n num] [-m num] [-s|-d] [-c -t num] -i <if>" << endl
            << "\t-i <if>\t\tnetwork interface" << endl
			<< "\t-h\t\tshow this info" << endl
            << "\t-n num\t\tnumber of packets to capture (default " << DEFAULT_PKT_CNT << ", -1 for unlimited)" << endl
            << "\t-a\t\tascending sort (default descending)" << endl
            << "\t-m num\t\tnumber of MACs to display in summary (all by default)" << endl
            << "\t-p\t\tshow percentage" << endl
            << "\t-r\t\tcount only remote ends (exclude my MACs)" << endl
            << "\t-l\t\tmark local MACs with asterisk (see also -r)" << endl
            << "\t-s\t\tshow only source stats" << endl
            << "\t-d\t\tshow only destination stats" << endl
            << "\t-c\t\tcontinuous mode" << endl
            << "\t-t\t\ttime delay for continuous mode in seconds (default "<< DEFAULT_DELAY << ")" << endl
            << "\t-v\t\tbe verbose (e.g. output each packet)" << endl
            << "\t-V\t\tprint version and exit" << endl
            << "\t-D\t\tenable debug output (you are not supposed to understand it)" << endl;
        exit(1);
    }

    cerr << "Listening on: " << pcap_dev << endl;

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
        perror("getifaddrs");
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
                //  printf ("%s:", ifap->ifa_name); device name
                for (i = 0; i < alen; i++, ap++)
                {
                    if (i > 0)
                        sprintf(ownmac+2+(i-1)*3,"%c%02x", ':' , 0xff&*ap);
                    else
                        sprintf(ownmac+i*3,"%02x", 0xff&*ap);
                }

                if (g_verbose)
                    cout << ownmac << endl;

                string ownmacstr(ownmac);
                ownmacs.insert(ownmacstr);
            }
        }
    }


    if (g_debug)
        copy(ownmacs.begin(), ownmacs.end(), ostream_iterator<string>(cout, "!\n"));

    freeifaddrs(ifaphead);

    // initialize pcap

    int pcap_net = pcap_lookupnet(pcap_dev, &net, &mask, errbuff);
    pcap_t *pcap_desc = pcap_open_live(pcap_dev, 100, 1, 1000, errbuff);
    if (pcap_desc == NULL) { perror("pcap_open_live"); exit(3); }

	if (g_cont)
	{
		signal(SIGALRM, alarm_report);
		alarm(time_delay);
	}

	pcap_loop(pcap_desc, pkt_cnt, h, NULL);
	report();   

    return 0;
}
