// $Id$
// system and C includes
#include <pcap.h>
#include <cstdio>
#include </usr/local/include/getopt.h>

// C++ includes
#include <string>
#include <iostream>
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

bool g_verbose = false;

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

template<class T> class print {	// utility for printing pairs to output stream
	ostream &os;
public:
	print(ostream &out) : os(out) {}
	void operator() (T x) { os << x.first << " " << x.second << endl; }
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
	int             pkt_cnt = 100;
	char           *pcap_dev = NULL;
	bpf_u_int32     net, mask;
	char            errbuff[1024];
	int 		opt;
	bool		usage = false; // show usage

	cerr << "Saker $Revision$"<< endl;

 	 while ((opt = getopt (argc, argv, "i:n:hv")) != -1)
    	{
      switch (opt)
        {
        case 'i':
          	pcap_dev = (char *) strdup (optarg);
          break;

	case 'n':
		pkt_cnt = atoi(optarg);
		break;
	case 'h':
		usage = true;
		break;
	case 'v':
		g_verbose = true;
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
			<< "\t-v\t\toptput each packet" << endl;
		exit(1);
	}

	int             pcap_net = pcap_lookupnet(pcap_dev, &net, &mask, errbuff);
	
	pcap_t         *pcap_desc = pcap_open_live(pcap_dev, 100, 1, 1000, errbuff);
	if (pcap_desc == NULL) { perror("pcap_open_live"); exit(1); }
	

	// do the capture
	pcap_loop(pcap_desc, pkt_cnt, h, NULL);


	cout << "SRC stats:" << endl;
	// we have first to copy all stats from src, which is ordered by MAC to src_score which is ordered by count, making possible printing stats ordered by count
	transform(src.begin(), src.end(), inserter(src_score, src_score.begin()), revert<string, int>());
	// and now we simply print stats by count :)
	for_each(src_score.begin(), src_score.end(), print<pair<int, string> >(cout));
	cout << "DST stats:" << endl;
	// same for dst
        transform(dst.begin(), dst.end(), inserter(dst_score, dst_score.begin()), revert<string, int>());
        for_each(dst_score.begin(), dst_score.end(), print<pair<int, string> >(cout));
}
