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
#include <stdint.h>
#include <sys/types.h>
#include <stdlib.h>

#include <string.h>

#ifdef WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

#include <ctype.h>

#include "namecoin.h"
#include "util.h"
#include "emcdns.h"
#include "hooks.h"
extern CHooks* hooks;

/*---------------------------------------------------*/

#define BUF_SIZE (512 + 512)
#define MAX_OUT  (512) // Old DNS restricts UDP to 512 bytes
#define MAX_TOK  64
#define VAL_SIZE (MAX_VALUE_LENGTH + 16)
#define DNS_PREFIX "dns"
#define REDEF_SYM  '~'

/*---------------------------------------------------*/

#ifdef WIN32
int inet_pton(int af, const char *src, void *dst)
{
  struct sockaddr_storage ss;
  int size = sizeof(ss);
  char src_copy[INET6_ADDRSTRLEN+1];

  ZeroMemory(&ss, sizeof(ss));
  /* stupid non-const API */
  strncpy (src_copy, src, INET6_ADDRSTRLEN+1);
  src_copy[INET6_ADDRSTRLEN] = 0;

  if (WSAStringToAddress(src_copy, af, NULL, (struct sockaddr *)&ss, &size) == 0) {
    switch(af) {
      case AF_INET:
    *(struct in_addr *)dst = ((struct sockaddr_in *)&ss)->sin_addr;
    return 1;
      case AF_INET6:
    *(struct in6_addr *)dst = ((struct sockaddr_in6 *)&ss)->sin6_addr;
    return 1;
    }
  }
  return 0;
}
#endif

/*---------------------------------------------------*/

EmcDns::EmcDns() : m_port(0) {
} // EmcDns::EmcDns

/*---------------------------------------------------*/

EmcDns::~EmcDns() {
  Reset(NULL, 0, NULL, NULL, 0);
} // EmcDns::~EmcDns


/*---------------------------------------------------*/

int EmcDns::Reset(const char *bind_ip, uint16_t port_no, const char *gw_suffix, const char *allowed_suff, uint8_t verbose) {
  if(m_port != 0) {
    // reset current object to initial state
#ifndef WIN32
    shutdown(m_sockfd, SHUT_RDWR);
#endif
    closesocket(m_sockfd);
    Sleep(100); // Allow 0.1s external thread to exit
#ifndef WIN32
    // pthread_join(m_thread, NULL);
#endif
    free(m_value);
    m_port = 0;
    if(m_verbose > 0)
	 printf("EmcDns::Reset: Destroyed OK\n");
  }

  if(port_no != 0) { 
    memset(this, 0, sizeof(this)); // Clear previous state
    m_verbose = verbose;
    // Create socket
    int ret = socket(PF_INET, SOCK_DGRAM, 0);
    if(ret < 0) {
      return -2; // Cannot create socket
    } else {
      m_sockfd = ret;
    }

    m_address.sin_family = AF_INET;
    m_address.sin_port = htons(port_no);

    if(!inet_pton(AF_INET, bind_ip, &m_address.sin_addr.s_addr)) 
      m_address.sin_addr.s_addr = htonl(INADDR_ANY);

    if(bind(m_sockfd, (struct sockaddr *) &m_address,
                     sizeof (struct sockaddr_in)) < 0) {
      char buf[80];
      sprintf(buf, "EmcDns::Reset: Cannot bind to port %u", port_no);
      perror(buf);
      closesocket(m_sockfd);
      return -3; // Cannot bind socket
    }

    // Create own lostener, only if GUI; 
    // Otherwise, Run() will be called from AppInit2
#ifdef QT_GUI
    // Create listener thread
    if (!CreateThread(StatRun, this))
    {
      perror("EmcDns::Reset: Cannot create thread");
      closesocket(m_sockfd);
      return -4; // cannot create inner thread
    }
#endif

    // Set object to a new state
    int allowed_len = allowed_suff == NULL? 0 : strlen(allowed_suff);
    m_gw_suf_len = gw_suffix == NULL? 0 : strlen(gw_suffix);

    m_value  = (char *)malloc(VAL_SIZE + BUF_SIZE + 2 + m_gw_suf_len + allowed_len + 3);
    if(m_value == NULL) {
      perror("EmcDns::Reset: Cannot allocate buffer");
      closesocket(m_sockfd);
      return -5; // no memory for buffers
    }
    m_buf    = (uint8_t *)(m_value + VAL_SIZE);
    m_bufend = m_buf + MAX_OUT;
    m_gw_suffix = m_gw_suf_len?
      strcpy(m_value + VAL_SIZE + BUF_SIZE + 2, gw_suffix) : NULL;
    
    // Create array of allowed suffixes
    if(allowed_len) {
      m_allowed_base = strcpy(m_value + VAL_SIZE + BUF_SIZE + 2 + m_gw_suf_len + 1, allowed_suff);
      uint8_t pos = 0, step = 0; // pos, step for double hashing
      for(char *p = m_allowed_base + allowed_len; p > m_allowed_base; ) {
	char c = *--p;
	if(c ==  '|' || c <= 040) {
	  *p = pos = step = 0;
	  continue;
	}
	if(c == '.') {
	  if(p[1] > 040) { // if allowed domain is not empty - save it into ht
	    step |= 1;
	    if(m_verbose > 3)
	      printf("\tEmcDns::Reset: Insert TLD=%s: pos=%u step=%u\n", p + 1, pos, step);
	    do 
	      pos += step;
            while(m_allowed_offset[pos] != 0);
	    m_allowed_offset[pos] = p + 1 - m_allowed_base;
	    m_allowed_qty++;
	  }
	  *p = pos = step = 0;
	  continue;
	}
        pos  = ((pos >> 7) | (pos << 1)) + c;
	step = ((step << 5) - step) ^ c; // (step * 31) ^ c
      } // for
    } // if(allowed_len)

    if(m_verbose > 0)
	 printf("EmcDns::Reset: Created/Attached: %s:%u; TLD_qty=%u\n", 
		 m_address.sin_addr.s_addr == INADDR_ANY? "INADDR_ANY" : bind_ip, 
		 port_no, m_allowed_qty);
  } // if(port_no != 0)
  
  return m_port = port_no;
} // EmcDns::Reset

/*---------------------------------------------------*/

void EmcDns::StatRun(void *p) {
  EmcDns *obj = (EmcDns*)p;
  obj->Run();
  ExitThread(0);
} // EmcDns::StatRun

/*---------------------------------------------------*/
void EmcDns::Run() {
  if(m_verbose > 2) printf("EmcDns::Run: started\n");
  for( ; ; ) {
    m_addrLen = sizeof(m_clientAddress);
    m_rcvlen  = recvfrom(m_sockfd, (char *)m_buf, BUF_SIZE, 0,
	            (struct sockaddr *) &m_clientAddress, &m_addrLen);
    if(m_rcvlen <= 0)
	break;

    m_buf[BUF_SIZE] = 0; // Set terminal for infinity QNAME

    HandlePacket();

    sendto(m_sockfd, (const char *)m_buf, m_snd - m_buf, MSG_NOSIGNAL,
	             (struct sockaddr *) &m_clientAddress, m_addrLen);
  } // for

  if(m_verbose > 2) printf("EmcDns::Run: Received Exit packet_len=%d\n", m_rcvlen);

} //  EmcDns::Run

/*---------------------------------------------------*/

void EmcDns::HandlePacket() {
  if(m_verbose > 2) printf("EmcDns::HandlePacket: Handle packet_len=%d\n", m_rcvlen);

  m_hdr = (DNSHeader *)m_buf;
  // Decode input header from network format
  m_hdr->Transcode();

  m_rcv = m_buf + sizeof(DNSHeader);
  m_rcvend = m_snd = m_buf + m_rcvlen;

  if(m_verbose > 3) {
    printf("\tEmcDns::HandlePacket: msgID  : %d\n", m_hdr->msgID);
    printf("\tEmcDns::HandlePacket: Bits   : %04x\n", m_hdr->Bits);
    printf("\tEmcDns::HandlePacket: QDCount: %d\n", m_hdr->QDCount);
    printf("\tEmcDns::HandlePacket: ANCount: %d\n", m_hdr->ANCount);
    printf("\tEmcDns::HandlePacket: NSCount: %d\n", m_hdr->NSCount);
    printf("\tEmcDns::HandlePacket: ARCount: %d\n", m_hdr->ARCount);
  }
  // Assert following 3 counters and bits are zero
//*  uint16_t zCount = m_hdr->ANCount | m_hdr->NSCount | m_hdr->ARCount | (m_hdr->Bits & (m_hdr->QR_MASK | m_hdr->TC_MASK));
  uint16_t zCount = m_hdr->ANCount | m_hdr->NSCount | (m_hdr->Bits & (m_hdr->QR_MASK | m_hdr->TC_MASK));

  // Clear answer counters - maybe contains junk from client
  //* m_hdr->ANCount = m_hdr->NSCount = m_hdr->ARCount = 0;
  m_hdr->ARCount = m_hdr->ANCount = m_hdr->NSCount = m_hdr->ARCount = 0;
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

  // Remove AR-section from request, if exist
  int ar_len = m_rcvend - m_rcv;

  if(ar_len < 0) {
      m_hdr->Bits |= 1; // Format error, RCV pointer is over
  }

  if(ar_len > 0) {
    memmove(m_rcv, m_rcvend, m_snd - m_rcvend);
    m_snd -= ar_len;
  }

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

  if(m_verbose > 0) printf("EmcDns::HandleQuery Key=%s QType=%x QClass=%x\n", key, qtype, qclass);

  if(qclass != 1)
    return 4; // Not implemented - support INET only

  // ToLower search key
  for(p = key + sizeof(DNS_PREFIX); *p; p++)
      if(*p >= 'A' && *p <= 'Z')
	  *p |= 040; // tolower

  if(m_gw_suf_len) { // suffix defined [public DNS], need to cut
    p -= m_gw_suf_len;
    if(p <= key + sizeof(DNS_PREFIX) || strcmp((const char *)p, m_gw_suffix) != 0) {
      if(m_verbose > 3) 
	  printf("EmcDns::HandleQuery: missing GW-suffix=%s in given key=%s; return NXDOMAIN\n", 
		  m_gw_suffix, key);
      return 3; // Invalid or missing domain suffix, return NXDOMAIN
    }
    *p = 0; // Cut suffix m_gw_sufix
  }

  if(m_allowed_qty) { // Activate TLD-filter
    uint8_t pos = 0, step = 0; // pos, step for double hashing
    while(*--p != '.') {
      if(p <= key + sizeof(DNS_PREFIX)) {
        if(m_verbose > 3) 
	  printf("EmcDns::HandleQuery: missing TLD-suffix in given key=%s; return NXDOMAIN\n", key);
	return 3; // No any suffix, so NXDOMAIN
      }
      pos  = ((pos >> 7) | (pos << 1)) + *p;
      step = ((step << 5) - step) ^ *p; // (step * 31) ^ c
    }

    p++; // Set PTR after dot, to the suffix
    step |= 1;

    do {
      pos += step;
      if(m_allowed_offset[pos] == 0) {
        if(m_verbose > 3) 
	  printf("EmcDns::HandleQuery: TLD-suffix in given key=%s is not allowed; return NXDOMAIN\n", key);
	return 3; // Reached EndOfList, so NXDOMAIN
      } 
    } while(strcmp((const char *)p, m_allowed_base + m_allowed_offset[pos]) != 0);
  } // if(m_allowed_qty)

  if(Search(key) <= 0) // Result saved into m_value
      return 3; // empty answer, not found, return NXDOMAIN

  { // Extract TTL
    char val2[VAL_SIZE];
    char *tokens[MAX_TOK];
    int ttlqty = Tokenize("TTL", NULL, tokens, strcpy(val2, m_value));
    m_ttl = htonl(ttlqty? atoi(tokens[0]) : 24 * 3600);
  }
  
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

  // Figure out main separator. If not defined, use |
  char mainsep[2];
  if(*buf == '~') {
    buf++;
    mainsep[0] = *buf++;
  } else
     mainsep[0] = '|';
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
     
      // if needed. redefine sep2
      char sepulka[2];
      if(*val == '~') {
	  *val++;
	  sepulka[0] = *val++;
	  sepulka[1] = 0;
	  sep2 = sepulka;
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

  if(m_verbose > 0) printf("EmcDns::Answer_ALL(QT=%d, key=%s); TokenQty=%d\n", qtype, key, tokQty);

  for(int tok_no = 0; tok_no < tokQty; tok_no++) {
      if(m_verbose > 1) 
	printf("\tEmcDns::Answer_ALL: Token:%u=[%s]\n", tok_no, tokens[tok_no]);
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
  if(m_verbose > 1) 
    printf("EmcDns::Search(%s)\n", key);

  string name((const char *)key);
  string value;
  if (!hooks->getNameValue(name, value))
    return 0;

  strcpy(m_value, value.c_str());
  return 1;
} //  EmcDns::Search

/*---------------------------------------------------*/

