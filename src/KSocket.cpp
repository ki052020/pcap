#include "pch.h"

#include "KException.h"
#include "KSocket.h"

// --------------------------------------------------------------------
KSocket::KSocket(const char* device, bool bPromiscFlag, bool bIpOnly)
{
   // ---------------------------------------
	// m_fd の取得
	if (bIpOnly)
	{
		// PF_PACKET, SOCK_RAW : L2 から生パケットを受け取る
		// ETH_P_IP : IP のみ
		// htons : バイトオーダーを、ネットワークバイトオーダーに変換する
      m_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	}
	else
	{
      // ETH_P_ALL : すべてのパケット
      m_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	}
   if (m_fd < 0)
      { THROW("!!! socket() < 0"); }

	// ---------------------------------------
	// ifreq の取得（インターフェイス index を取得する）
	ifreq ifreq;  // ioctl用
	memset(&ifreq, 0, sizeof(struct ifreq));
	strncpy(ifreq.ifr_name, device, sizeof(ifreq.ifr_name) - 1);

	// SIOCGIFINDEX : インターフェースの interface index を取得する
	if(ioctl(m_fd, SIOCGIFINDEX, &ifreq) < 0)
	{
      close(m_fd);
      m_fd = -1;  // 念のため
      THROW("!!! ioctl() < 0 / confirm device-name");
	}

	// ---------------------------------------
	sockaddr_ll sa;  // リンクレベルヘッダ情報
	sa.sll_family = PF_PACKET;
	if (bIpOnly)
		{ sa.sll_protocol = htons(ETH_P_IP); }
	else
		{ sa.sll_protocol = htons(ETH_P_ALL); }
	
	sa.sll_ifindex = ifreq.ifr_ifindex;  // sll_ifindex : インターフェイス index
	if (bind(m_fd, (sockaddr*)&sa, sizeof(sa)) < 0)
	{
      close(m_fd);
      m_fd = -1;  // 念のため
      THROW("!!! bind() < 0");
	}

	// ---------------------------------------
	if (bPromiscFlag)
	{
		// SIOCGIFFLAGS : デバイスの active フラグワードを取得
		if(ioctl(m_fd, SIOCGIFFLAGS, &ifreq) < 0)
		{
         close(m_fd);
         m_fd = -1;  // 念のため
         THROW("!!! ioctl() < 0");
      }

		ifreq.ifr_flags = ifreq.ifr_flags | IFF_PROMISC;
		// SIOCSIFFLAGS : デバイスの active フラグワードを設定
		if(ioctl(m_fd, SIOCSIFFLAGS, &ifreq) < 0)
		{
         close(m_fd);
         m_fd = -1;  // 念のため
         THROW("!!! ioctl() < 0");
		}
	}
}

// --------------------------------------------------------------------
KSocket::~KSocket()
{
   if (m_fd >= 0) { close(m_fd); }
}

