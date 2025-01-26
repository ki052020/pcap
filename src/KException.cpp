#define BOOST_STACKTRACE_USE_BACKTRACE
#include <boost/stacktrace.hpp>

#include "KException.h"

// --------------------------------------------------------------------
KException::KException(const char* pmsg)
	: m_msg{ pmsg }
{
	boost::stacktrace::basic_stacktrace bt = boost::stacktrace::stacktrace();
	m_pcs_bts = bt.size() - 1;
	if (m_pcs_bts > EN_max_pcs_bts) { m_pcs_bts = EN_max_pcs_bts; }

	for (int i = 1; i <= m_pcs_bts; ++i)
	{
		std::string str_bt;
		str_bt.reserve(100);  // 暫定的な処置
		str_bt += bt[i].name() + " " + bt[i].source_file()
				+ " -line " + std::to_string(bt[i].source_line()) + "\n";

		m_bts.push_back(str_bt);
	}
}

// --------------------------------------------------------------------
void KException::Show() const
{
	printf(m_msg.c_str());
	printf("\n\n[stack trace]\n");

	for (auto str : m_bts)
		{ printf(str.c_str()); }

	printf("\n");
}
