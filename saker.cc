// $Id$

// system and C includes
#include <pcap.h>
#include <cstdio>
#include </usr/local/include/getopt.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <net/if_dl.h>
	
// C++ includes
#include <string>
#include <iostream>
#include <set>
#include <map>
#include <algorithm>
#include <iterator>

using namespace std;

map<string, int> src; 	// container that keeps pairs (MAC, count) representing src 
			// addresses of packets ordered by MAC adress
map<string, int> dst; 	// same for dst addresses
multimap<int, string> src_score; 	// container that keeps pairs (MAC, count)
					// representing src addresses of packets
					// ordered by count of packets
multimap<int, string> dst_score;	// same for dst addresses

set<string> ownmacs; // keeps list of own macs (for -r handling) 

bool g_verbose = false;
bool g_remote = false;
bool g_mark = false;
bool g_debug = false;
bool g_ascend = false;
bool g_percent = false;
int  pkt_cnt = 100;
int  src_cnt;
int  dst_cnt;
	
void 
h(u_char * useless, const struct pcap_pkthdr * pkthdr, const u_char * pkt)
{
	char buf[50];
	int             i;
	map<string, int>::iterator mit;
	for (i = 0; i < 6; i++)
		sprintf(buf+3*i, "%02x:", pkt[i]);
	buf[17] = '\0';
	string s1(buf);
	mit=src.find(s1);	// find element of src having MAC equal to s1
	if (mit == src.end())	// not found, create
		src.insert(make_pair(s1, 1));
	else			// found, increase count by 1
		++(mit -> second);

	for (i = 0; i < 6; i++)
		sprintf(buf+3*i, "%02x:", pkt[i + 6]);
	buf[17] = '\0';
	string s2(buf);
        mit=dst.find(s2);	// same for dst
        if (mit == dst.end())
                dst.insert(make_pair(s2, 1));
        else
                ++(mit -> second);
	
	if (g_verbose)
		cout << s1 << " ->> " << s2 << endl;
}

template<class T> class uncount {
	int* cnt_var;
public:
	uncount(int* cv) : cnt_var(cv) {}
	void operator() (T x) {
		if (ownmacs.find(x.second) != ownmacs.end()) {
			*cnt_var = *cnt_var - x.first;
			if (g_debug)
				cout << "DEBUG uncount: " << x.first << " " << *cnt_var << endl;
		}
	}
};

template<class T> class print {	// utility for printing pairs to output stream
	ostream &os;
	int pkt_cnt;
public:
	print(ostream &out, int pc) : os(out), pkt_cnt(pc) {}
	void operator() (T x) {
		if (g_remote)
			if (ownmacs.find(x.second) != ownmacs.end()) {
				if (g_debug)
					cout << "DEBUG: erased: " << x.second << endl;
				return;
			}
		os << "\t" << x.first << "\t" << x.second;
		if (g_percent) {
			char s[10];
			sprintf(s, "%4.1f", (static_cast<double>(x.first)/pkt_cnt)*100.0);
			cout << "\t" << s << "%";
		}	
		if (g_mark)
                        if (ownmacs.find(x.second) != ownmacs.end())
                                cout << " *";
	        cout << endl; 
	}
};

template <class T, class S> class revert {  // utility for reverting pairs
// input:  pair (A, B)
// output: pair (B, A)
public:
	revert() {}
	pair<S, T> operator() (pair<T, S> x) {
		return make_pair(x.second, x.first);
	}
};

int 
main(int argc, char *argv[])
{
//	int             pkt_cnt = 100; // obecnie w zasiegu globalnym (g_percent)!
	char           *pcap_dev = NULL;
	bpf_u_int32     net, mask;
	char            errbuff[1024];
	int 		opt;
	bool		usage = false; // show usage

	cerr << "Saker $Revision$"<< endl;

 	 while ((opt = getopt (argc, argv, "i:n:aphvrmd")) != -1)
    	{
      switch (opt)
        {
        case 'i':
          	pcap_dev = (char *) strdup (optarg);
          break;

	case 'n':
		pkt_cnt = atoi(optarg);
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
	case 'm':
		g_mark = true;
		break;
	case 'd':
		g_debug = true;
		break;
        default:
          cerr << "Error: Unknown command line option." << endl;
	  usage = true;
          break;
        }
    }
	
	if (pcap_dev == NULL)
	{
		cerr << "Error: Interface not specified." << endl;
		usage = true;
	}

	if (usage)
	{
		cerr << "Usage: saker -i <if> [-n num] [-v]" << endl
			<< "\t-i <if>\t\tnetwork interface" << endl
			<< "\t-n num\t\tnumber of packets to capture" << endl
			<< "\t-a\t\tascending sort (default descending)" << endl
			<< "\t-p\t\tshow percentage" << endl
			<< "\t-r\t\tcount only remote ends (exclude my MACs)" << endl
			<< "\t-m\t\tmark my MACs with star (see also -r)" << endl
			<< "\t-v\t\tbe verbose (e.g. output each packet)" << endl
			<< "\t-d\t\tenable debug output (you are not supposed to understand it)" << endl;
		exit(1);
	}


// get own mac's
	
  struct ifaddrs *ifap, *ifaphead;
  int rtnerr;
  const struct sockaddr_dl *sdl;
  caddr_t ap;
  int alen;
  char ownmac[18] = "..:..:..:..:..:.."; // 6*2+5+1

  rtnerr = getifaddrs(&ifaphead);
  if (rtnerr) {
    perror(NULL);
    return 1;
  }

  if (g_verbose)
	  cout << "Own MAC adresses:" << endl;
  for (ifap = ifaphead; ifap; ifap = ifap->ifa_next) 
  {
    if (ifap->ifa_addr->sa_family == AF_LINK) {
      sdl = (const struct sockaddr_dl *) ifap->ifa_addr;
      ap = ((caddr_t)((sdl)->sdl_data + (sdl)->sdl_nlen));
      alen = sdl->sdl_alen;
      if (ap && alen > 0) {
        int i;

//        printf ("%s:", ifap->ifa_name); device name
        for (i = 0; i < alen; i++, ap++) {
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
    
 
	
	int             pcap_net = pcap_lookupnet(pcap_dev, &net, &mask, errbuff);
	
	pcap_t         *pcap_desc = pcap_open_live(pcap_dev, 100, 1, 1000, errbuff);
	if (pcap_desc == NULL) { perror("pcap_open_live"); exit(1); }
	

	// do the capture
	pcap_loop(pcap_desc, pkt_cnt, h, NULL);

/*******************************
 * begin of the report section *
 *******************************/
	
	cout << "SRC stats:" << endl;
	src_cnt = pkt_cnt;
	// we have first to copy all stats from src, which is ordered by MAC to src_score which is ordered by count, making possible printing stats ordered by count
	transform(src.begin(), src.end(), inserter(src_score, src_score.begin()), revert<string, int>());
	if (g_remote)
		for_each(src_score.begin(), src_score.end(), uncount<pair<int, string> >(&src_cnt));
	// and now we simply print stats by count :)
	if (g_ascend)
		for_each(src_score.begin(), src_score.end(), print<pair<int, string> >(cout, src_cnt));
	else
		for_each(src_score.rbegin(), src_score.rend(), print<pair<int, string> >(cout, src_cnt));
	cout << "DST stats:" << endl;
	dst_cnt = pkt_cnt;
	// same for dst
        transform(dst.begin(), dst.end(), inserter(dst_score, dst_score.begin()), revert<string, int>());
        if (g_remote)
                for_each(dst_score.begin(), dst_score.end(), uncount<pair<int, string> >(&dst_cnt))
;
	if (g_ascend)
		for_each(dst_score.begin(), dst_score.end(), print<pair<int, string> >(cout, dst_cnt));
	else
		for_each(dst_score.rbegin(), dst_score.rend(), print<pair<int, string> >(cout, dst_cnt));
}
