#pragma once

// --------------------------------------------------------------------
// 現時点では、ソケットのクローズを確実にするためだけに存在している
class KSocket
{
public:
   KSocket(const char* device, bool bPromiscFlag, bool bIpOnly);
   ~KSocket();

   int fd() const { return m_fd; }

private:
   int m_fd = -1;
};
