#include <plugin.h>

#include <lib/gui/ewindow.h>
#include <lib/gui/listbox.h>
#include <lib/gui/ebutton.h>
#include <lib/gui/emessage.h>
#include <lib/system/econfig.h>
#include <lib/system/httpd.h>

class eHTTPDownloadInfo: public eHTTPDataSource
{
	eString *value;
public:
	int error;
	eHTTPDownloadInfo(eHTTPConnection *c, eString *value);
	void haveData(void *data, int len);
	//int doWrite(int val);
};

class eGenuineDreambox: public eWindow
{
	eLabel *le;
	eButton *b_start;
	eTimer *step_timer;

	int error;
	int count;
	int sockfd;
	eString value;

	eHTTPConnection *http;
	eHTTPDownloadInfo *datainfo;
	eHTTPDataSource *createInfoDataSink(eHTTPConnection *conn);
	void infoTransferDone(int err);
	
	void setError(int err);
	void setStatus(const eString &string);
	void startDownload(const eString &url);
	void start();
	void nextStep();
public:
	eGenuineDreambox();
	~eGenuineDreambox();
};
