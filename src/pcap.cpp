#include "pch.h"  // プリコンパイル済みヘッダ

#include "KException.h"
#include "KSocket.h"

#include	"analyze.h"

extern void Test();

// --------------------------------------------------------------------
// main
// arvv[1] = device名
int main(int argc, char* argv[], char* envp[])
{
//	Test();

	// ---------------------------------------
	if (argc <= 1)
	{
		fprintf(stderr,"pcap device-name\n");
		return 1;
	}

	try
	{
		// ---------------------------------------
		// arvv[1] = device名
		KSocket soc{ argv[1], false, false };

		// ---------------------------------------
		u_char buf[65535];
		for (int i = 5; i > 0; --i)
		{
			const int size = read(soc.fd(), buf, sizeof(buf));
			if (size <= 0)
				{ THROW("!!! read() < 0"); }
			else
				{ AnalyzePacket(buf, size); }
		}
	}
	catch(const KException& ex)
	{
		ex.Show();
	}

	return 0;
}
