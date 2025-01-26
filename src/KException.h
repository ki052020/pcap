#pragma once

#include <string>
#include <vector>

// --------------------------------------------------------------------
class KException
{
	enum { EN_max_pcs_bts = 8 };

public:
	KException(const char* pmsg);
	KException(std::string msg) : KException(msg.c_str()) {}

	void Show() const;

private:
	std::string m_msg;

	// backtrace 情報
	int m_pcs_bts;
	std::vector<std::string> m_bts;
};

// --------------------------------------------------------------------
#define THROW( msg ) throw KException{ msg }

