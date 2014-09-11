/*
 * Simple DNS server for EmerCoin project
 *
 * Lookup for names like "dns:some-nake" in the local nameindex database.
 * Database is updates from blockchain, and keeps NMC-transactions.
 *
 * Supports standard RFC1034 UDP DNS protocol only
 *
 * Supported fields: A, AAAA, NS, PTR, MX, TXT, CNAME
 * Does not support: SOA, WKS, SRV
 * Does not support recursive query, authority zone and namezone transfers.
 * 
 *
 * Author: maxihatop
 *
 * This code can be used according BSD license:
 * http://en.wikipedia.org/wiki/BSD_licenses
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>

#include <string.h>

#include <arpa/inet.h>
#include <ctype.h>

/*---------------------------------------------------*/

#define BUF_SIZE (512 + 512)
#define MAX_OUT  (512) // Old DNS restricts UDP to 512 bytes
#define MAX_TOK  64
#define VAL_SIZE (22 * 1024)
#define DNS_PREFIX "dns"
/*---------------------------------------------------*/

struct DNSHeader {
  static const uint QR_MASK = 0x8000;
  static const uint OPCODE_MASK = 0x7800; // shr 11
  static const uint AA_MASK = 0x0400;
  static const uint TC_MASK = 0x0200;
  static const uint RD_MASK = 0x0100;
  static const uint RA_MASK = 0x8000;
  static const uint RCODE_MASK = 0x000F;

  uint16_t msgID;
  uint16_t Bits;
  uint16_t QDCount;
  uint16_t ANCount;
  uint16_t NSCount;
  uint16_t ARCount;

  inline void Transcode() {
    for(uint16_t *p = &msgID; p <= &ARCount; *p++)
      *p = ntohs(*p);
  }
}; // struct DNSHeader 

class EmcDns {
  public:
     EmcDns();
    ~EmcDns();

    int Reset(uint16_t port_no);

  private:
    static void *StatRun(void *p);
    void Run(); 
    void HandlePacket();
    uint16_t HandleQuery();
    int  Search(uint8_t *key);
    int  Tokenize(const char *key, const char *sep2, char **tokens, char *buf);
    void Answer_ALL(uint16_t qtype, char *buf);
    void Fill_RD_IP(char *ipddrtxt, int af);
    void Fill_RD_DName(char *txt, uint8_t mxsz, int8_t txtcor);

    inline void Out2(uint16_t x) { memcpy(m_snd, &x, 2); m_snd += 2; }
    inline void Out4(uint32_t x) { memcpy(m_snd, &x, 4); m_snd += 4; }

    DNSHeader *m_hdr;
    char     *m_value;
    uint8_t  *m_buf, *m_bufend, *m_snd, *m_rcv, *m_rcvend;
    pthread_t m_thread;
    int       m_sockfd;
    int       m_rcvlen;
    uint32_t  m_ttl;
    uint16_t  m_port;
    uint16_t  m_label_ref;
    struct sockaddr_in m_clientAddress;
    struct sockaddr_in m_address;
    socklen_t m_addrLen;
}; // class EmcDns


/*---------------------------------------------------*/



/*---------------------------------------------------*/

EmcDns::EmcDns() {
  m_port = 0;
  m_value  = (char *)malloc(VAL_SIZE + BUF_SIZE + 2);
  m_buf    = (uint8_t *)(m_value + VAL_SIZE); 
  m_bufend = m_buf + MAX_OUT;
  printf("EmcDns created\n");
} // EmcDns::EmcDns

/*---------------------------------------------------*/

EmcDns::~EmcDns() {
  Reset(0);
  free(m_value);
  printf("EmcDns destroyed\n");
} // EmcDns::~EmcDns


/*---------------------------------------------------*/

int EmcDns::Reset(uint16_t port_no) {
  if(m_port != 0) {
    // reset current object to initial state
    shutdown(m_sockfd, SHUT_RDWR);
    close(m_sockfd);
    pthread_join(m_thread, NULL);
    printf("join OK\n");
    m_port = 0;
  }

  if(port_no != 0) { 
    // Set object to a new state
    if(m_value == NULL)
      return -1; // no memory for buffers
    // Create socket
    m_sockfd = socket(PF_INET, SOCK_DGRAM, 0);
    if(m_sockfd < 0) {
      return -2; // Cannot create socket
    }

    m_address.sin_family = AF_INET;
    m_address.sin_addr.s_addr = INADDR_ANY;
    m_address.sin_port = htons(port_no);

    if(bind(m_sockfd, (struct sockaddr *) &m_address,
                     sizeof (struct sockaddr_in)) < 0) {
      close(m_sockfd);
      return -3; // Cannot bind socket
    }

    // Create listener thread
    if(pthread_create(&m_thread, NULL, StatRun, this) < 0) {
      close(m_sockfd);
      return -4; // cannot create inner thread
    }

  } // if(port_no != 0)
  
  return m_port = port_no;
} // EmcDns::Reset

/*---------------------------------------------------*/

void *EmcDns::StatRun(void *p) {
  EmcDns *obj = (EmcDns*)p;
  obj->Run();
  return NULL;
} // EmcDns::StatRun

/*---------------------------------------------------*/
void EmcDns::Run() {
  printf("EmcDns Called RUN\n");
  for( ; ; ) {
    m_addrLen = sizeof(m_clientAddress);
    m_rcvlen  = recvfrom(m_sockfd, m_buf, BUF_SIZE, 0,
	            (struct sockaddr *) &m_clientAddress, &m_addrLen);
    if(m_rcvlen <= 0)
	break;

    m_buf[BUF_SIZE] = 0; // Set terminal for infinity QNAME

    HandlePacket();

    sendto(m_sockfd, m_buf, m_snd - m_buf, MSG_NOSIGNAL, 
	             (struct sockaddr *) &m_clientAddress, m_addrLen);
  } // for

  printf("Received2 packet=%d\n", m_rcvlen);
  pthread_exit(NULL);
} //  EmcDns::Run

/*---------------------------------------------------*/

void EmcDns::HandlePacket() {
  printf("Received/HANDLE packet=%d\n", m_rcvlen);

  m_hdr = (DNSHeader *)m_buf;
  // Decode input header from network format
  m_hdr->Transcode();

  m_rcv = m_buf + sizeof(DNSHeader);
  m_rcvend = m_snd = m_buf + m_rcvlen;

  printf("msgID  : %d\n", m_hdr->msgID);
  printf("Bits   : %04x\n", m_hdr->Bits);
  printf("QDCount: %d\n", m_hdr->QDCount);
  printf("ANCount: %d\n", m_hdr->ANCount);
  printf("NSCount: %d\n", m_hdr->NSCount);
  printf("ARCount: %d\n", m_hdr->ARCount);

  // Assert following 3 counters iand bits are zero
  uint16_t zCount = m_hdr->ANCount | m_hdr->NSCount | m_hdr->ARCount | (m_hdr->Bits & (m_hdr->QR_MASK | m_hdr->TC_MASK));

  // Clear answer counters - maybe contains junk from client
  m_hdr->ANCount = m_hdr->NSCount = m_hdr->ARCount = 0;
  m_hdr->Bits   |= m_hdr->QR_MASK; // Change Q->R

  do {
    // check flags QR=0 and TC=0
    if(m_hdr->QDCount == 0 || zCount != 0) {
      m_hdr->Bits |= 1; // Format error, expected request
      break;
    }

    uint16_t opcode = m_hdr->Bits & m_hdr->OPCODE_MASK;

    if(opcode != 0) {
      m_hdr->Bits |= 4; // Not implemented; handle standard query only
      break;
    }

    // Handle questions here
    for(uint16_t qno = 0; qno < m_hdr->QDCount && m_snd < m_bufend; qno--) {
      uint16_t rc = HandleQuery();
      if(rc) {
	m_hdr->Bits |= rc;
	break;
      }
    }
  } while(false);

  // Truncate answer, if needed
  if(m_snd >= m_bufend) {
    m_hdr->Bits |= m_hdr->TC_MASK;
    m_snd = m_buf + MAX_OUT;
  }
  // Encode output header into network format
  m_hdr->Transcode();
} // EmcDns::HandlePacket

/*---------------------------------------------------*/
uint16_t EmcDns::HandleQuery() {
  // Decode qname
  uint8_t key[BUF_SIZE];
  strcpy((char *)key, DNS_PREFIX); 
  uint8_t *keyp = key + sizeof(DNS_PREFIX) - 1;
  uint8_t *p = keyp;
  strncpy((char *)keyp, (const char *)m_rcv, BUF_SIZE - sizeof(DNS_PREFIX));

  for(uint8_t sep = ':'; *p != 0; ) {
    uint8_t sym = *p;
    *p = sep; 
    sep = '.';
    p += sym + 1;
    if((sym & 0xc0) || p >= key + BUF_SIZE - sizeof(DNS_PREFIX))
      return 1; // Invalid request
  }

  m_label_ref = htons((m_rcv - m_buf) | 0xc000);
  m_rcv += p - keyp + 1; // Promote to end of QNAME

  uint16_t qtype  = *m_rcv++; qtype  = (qtype  << 8) + *m_rcv++; 
  uint16_t qclass = *m_rcv++; qclass = (qclass << 8) + *m_rcv++;

  printf("HandleQuery: D=%s QT=%x QC=%x\n", key, qtype, qclass);

  if(qclass != 1)
    return 4; // Not implemented - support INET only

  if(Search(key) <= 0) // Result saved into m_value
      return 3; // empty answer, not found, return NXDOMAIN

  { // Extract TTL
    char val2[VAL_SIZE];
    char *tokens[MAX_TOK];
    int ttlqty = Tokenize("TTL", NULL, tokens, strcpy(val2, m_value));
    m_ttl = htonl(ttlqty? atoi(tokens[0]) : 24 * 3600);
  }
  
  // printf("TTL=%u\n", ntohl(m_ttl));

  if(qtype == 0xff) { // ALL Q-types
    char val2[VAL_SIZE];
    // List values for ANY:    A NS CNA PTR MX AAAA
    const uint16_t q_all[] = { 1, 2, 5, 12, 15, 28, 0 };
    for(const uint16_t *q = q_all; *q; q++)
      Answer_ALL(*q,  strcpy(val2, m_value));
  } else 
      Answer_ALL(qtype, m_value);
  return 0;
} // EmcDns::HandleQuery
/*---------------------------------------------------*/

int EmcDns::Tokenize(const char *key, const char *sep2, char **tokens, char *buf) {
  int tokensN = 0;

  char mainsep[2];
  if(isalpha(*buf))
    mainsep[0] = '|';
  else
    mainsep[0] = *buf++;
  mainsep[1] = 0;

  for(char *token = strtok(buf, mainsep);
    token != NULL; 
      token = strtok(NULL, mainsep)) {
      // printf("Token:%s\n", token);
      char *val = strchr(token, '=');
      if(val == NULL)
	  continue;
      *val = 0;
      if(strcmp(key, token)) {
	  *val = '=';
	  continue;
      }
      val++;
      // Uplevel token found, tokenize value if needed
      // printf("Found: key=%s; val=%s\n", key, val);
      if(sep2 == NULL || *sep2 == 0) {
	tokens[tokensN++] = val;
	break;
      }
      // Tokenize value
      for(token = strtok(val, sep2); 
	 token != NULL && tokensN < MAX_TOK; 
	   token = strtok(NULL, sep2)) {
	  // printf("Subtoken=%s\n", token);
	  tokens[tokensN++] = token;
      }
      break;
  } // for - big tokens (MX, A, AAAA, etc)
  return tokensN;
} // EmcDns::Tokenize

/*---------------------------------------------------*/

void EmcDns::Answer_ALL(uint16_t qtype, char *buf) {
  const char *key;
  switch(qtype) {
      case  1 : key = "A";      break;
      case  2 : key = "NS";     break;
      case  5 : key = "CNAME";  break;
      case 12 : key = "PTR";    break;
      case 15 : key = "MX";     break;
      case 16 : key = "TXT";    break;
      case 28 : key = "AAAA";   break;
      default: return;
  } // swithc

  char *tokens[MAX_TOK];
  int tokQty = Tokenize(key, ",", tokens, buf);

  printf("Exec: Answer_ALL(%d, %s)=%d\n", qtype, key, tokQty);

  for(int tok_no = 0; tok_no < tokQty; tok_no++) {
      printf("  Answer_ALL(%d):%d:[%s]\n", qtype, tok_no, tokens[tok_no]);
      Out2(m_label_ref);
      Out2(htons(qtype)); // A record
      Out2(htons(1)); //  INET
      Out4(m_ttl);
      switch(qtype) {
	case 1 : Fill_RD_IP(tokens[tok_no], AF_INET);  break;
	case 28: Fill_RD_IP(tokens[tok_no], AF_INET6); break;
	case 2 :
	case 5 :
	case 12: Fill_RD_DName(tokens[tok_no], 0, 0); break; // NS,CNAME,PTR
	case 15: Fill_RD_DName(tokens[tok_no], 2, 0); break; // MX
	case 16: Fill_RD_DName(tokens[tok_no], 0, 1); break; // TXT
	default: break;
      } // swithc
  } // for
  m_hdr->ANCount += tokQty;
} // EmcDns::Answer_A 

/*---------------------------------------------------*/

void EmcDns::Fill_RD_IP(char *ipddrtxt, int af) {
  uint16_t out_sz;
  switch(af) {
      case AF_INET : out_sz = 4;  break;
      case AF_INET6: out_sz = 16; break;
      default: return;
  }
  Out2(htons(out_sz));
  if(inet_pton(af, ipddrtxt, m_snd)) 
    m_snd += out_sz;
  else
    m_snd -= 2, m_hdr->ANCount--;
#if 0  
  return;

  in_addr_t inetaddr = inet_addr(ipddrtxt);
  Out2(htons(sizeof(inetaddr)));
  Out4(inetaddr);
#endif
} // EmcDns::Fill_RD_IP

/*---------------------------------------------------*/

void EmcDns::Fill_RD_DName(char *txt, uint8_t mxsz, int8_t txtcor) {
  uint8_t *snd0 = m_snd;
  m_snd += 3 + mxsz; // skip SZ and sz0
  uint8_t *tok_sz = m_snd - 1;
  uint16_t mx_pri = 1; // Default MX priority
  char c;

  uint8_t *bufend = m_snd + 255;

  if(m_bufend < bufend)
    bufend = m_bufend;

  do {
    c = *m_snd++ = *txt++;
    if(c == '.') {
      *tok_sz = m_snd - tok_sz - 2;
      tok_sz  = m_snd - 1;
    }
    if(c == ':' && mxsz) { // split for MX only
      c = m_snd[-1] = 0;
      mx_pri = atoi(txt);
    }
  } while(c && m_snd < bufend);

  *tok_sz = m_snd - tok_sz - 2;

  // Remove trailing \0 at end of text
  m_snd -= txtcor;

  uint16_t len = m_snd - snd0 - 2;
  *snd0++ = len >> 8;
  *snd0++ = len;
  if(mxsz) {
    *snd0++ = mx_pri >> 8;
    *snd0++ = mx_pri;
  }
} // EmcDns::Fill_RD_DName

/*---------------------------------------------------*/
/*---------------------------------------------------*/

int EmcDns::Search(uint8_t *key) {
  // strcpy(m_value, "TXT=This is text|MX=127.0.0.1:3333,127.0.0.2|CNAME=emc.cc.st|PTR=olegh.cc.st,avalon.cc.st|A=192.168.0.120,127.0.0.1|AAAA=2607:f8b0:4004:806::1001|NS=ns1.google.com|TTL=4001");
  strcpy(m_value, "/TXT=This is text/MX=yandex.ru:33,mx.lenta.ru:66/CNAME=emc.cc.st/PTR=olegh.cc.st,avalon.cc.st/A=192.168.0.120,127.0.0.1/AAAA=2607:f8b0:4004:806::1001/NS=ns1.google.com/TTL=4001");
  return 1;
} //  EmcDns::Search


/*---------------------------------------------------*/

int main(int argc, char **argv) {
  printf("Main started\n");
  EmcDns dnssrv;
  int rc = dnssrv.Reset(5353);
  printf("dnssrv.Reset executed=%d\n", rc);
  if(rc < 0) perror("Error code");
  sleep(200);
  // dnssrv.Reset(0);
  printf("Main exited\n");
  return 0;
}

/*---------------------------------------------------*/
