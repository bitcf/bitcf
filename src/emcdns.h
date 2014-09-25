#ifndef EMCDNS_H
#define EMCDNS_H

struct DNSHeader {
  static const uint32_t QR_MASK = 0x8000;
  static const uint32_t OPCODE_MASK = 0x7800; // shr 11
  static const uint32_t AA_MASK = 0x0400;
  static const uint32_t TC_MASK = 0x0200;
  static const uint32_t RD_MASK = 0x0100;
  static const uint32_t RA_MASK = 0x8000;
  static const uint32_t RCODE_MASK = 0x000F;

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
} __attribute__((packed)); // struct DNSHeader

class EmcDns {
  public:
     EmcDns();
    ~EmcDns();

    int Reset(const char *bind_ip, uint16_t port_no, const char *gw_suffix, uint8_t verbose); 

  private:
    static void StatRun(void *p);
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
    const char *m_gw_suffix;
    uint8_t  *m_buf, *m_bufend, *m_snd, *m_rcv, *m_rcvend;
    SOCKET    m_sockfd;
    int       m_rcvlen;
    uint32_t  m_ttl;
    uint16_t  m_port;
    uint16_t  m_label_ref;
    uint16_t  m_gw_suf_len;
    uint8_t   m_verbose;
    uint8_t   m_reserved;
    struct sockaddr_in m_clientAddress;
    struct sockaddr_in m_address;
    socklen_t m_addrLen;
}; // class EmcDns

#endif // EMCDNS_H

