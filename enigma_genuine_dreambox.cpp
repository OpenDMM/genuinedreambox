#include <enigma_genuine_dreambox.h>

#include "tpmd.h"
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <lib/gdi/font.h>

//#define TPMDEBUG	1
#define PROD_VERSION	1
#define DMM_URL		"http://www.dream-multimedia-tv.de/verify/challenge?"
#define BASE64_BUF(x)	(((x)+2)/3*4+1)

static void send_cmd(int fd, enum tpmd_cmd cmd, const void *data, unsigned int len)
{
	unsigned char buf[len + 4];

	buf[0] = (cmd >> 8) & 0xff;
	buf[1] = (cmd >> 0) & 0xff;
	buf[2] = (len >> 8) & 0xff;
	buf[3] = (len >> 0) & 0xff;
	memcpy(&buf[4], data, len);

	if (write(fd, buf, sizeof(buf)) != (ssize_t)sizeof(buf))
		fprintf(stderr, "%s: incomplete write\n", __func__);
}

static void *recv_cmd(int fd, unsigned int *tag, unsigned int *len)
{
	unsigned char buf[4];
	void *val;

	if (read(fd, buf, 4) != 4)
		fprintf(stderr, "%s: incomplete read\n", __func__);

	*tag = (buf[0] << 8) | buf[1];
	*len = (buf[2] << 8) | buf[3];

	val = malloc(*len);
	if (read(fd, val, *len) != (ssize_t)*len)
		fprintf(stderr, "%s: incomplete read\n", __func__);

	return val;
}


static int parse_data(const unsigned char *data, unsigned int datalen, int *prot_version, int *tpm_version, unsigned long *serial, void *cert_l2, void *cert_l3, void *cert_fab, void *datablock)
{
	unsigned int i, j;
	unsigned int tag;
	unsigned int len;
	const unsigned char *val;

	for (i = 0; i < datalen; i += len) {
		tag = data[i++];
		len = data[i++];
		val = &data[i];

#if TPMDEBUG
		printf("tag=%02x len=%02x val=", tag, len);
		for (j = 0; j < len; j++)
			printf("%02x", val[j]);
		printf("\n");
#endif

		switch (tag) {
		case TPMD_DT_PROTOCOL_VERSION:
			if (len != 1)
				break;
#if TPMDEBUG
			printf("protocol version: %d\n", val[0]);
#endif
			if (prot_version)
			{
				*prot_version = val[0];
				prot_version = 0;
			}
			break;
		case TPMD_DT_TPM_VERSION:
			if (len != 1)
				break;
#if TPMDEBUG
			printf("tpmd version: %d\n", val[0]);
#endif
			if (tpm_version)
			{
				*tpm_version = val[0];
				tpm_version = 0;
			}
			break;
		case TPMD_DT_SERIAL:
			if (len != 4)
				break;
#if TPMDEBUG
			printf("serial: %d\n", (val[0] << 24) | (val[1] << 16) | (val[2] << 8) | val[3]);
#endif
			if (serial)
			{
				*serial = (val[0] << 24) | (val[1] << 16) | (val[2] << 8) | val[3];
				serial = 0;
			}
			break;
		case TPMD_DT_LEVEL2_CERT:
			if (len != 210)
				break;
			if (cert_l2)
			{
				memcpy(cert_l2, val, 210);
				cert_l2 = 0;
			}
			break;
		case TPMD_DT_LEVEL3_CERT:
			if (len != 210)
				break;
			if (cert_l3)
			{
				memcpy(cert_l3, val, 210);
				cert_l3 = 0;
			}
			break;
		case TPMD_DT_FAB_CA_CERT:
			if (len != 210)
				break;
			if (cert_fab)
			{
				memcpy(cert_fab, val, 210);
				cert_fab = 0;
			}
			break;
		case TPMD_DT_DATABLOCK_SIGNED:
			if (len != 128)
				break;
			if (datablock)
			{
				memcpy(datablock, val, 128);
				datablock = 0;
			}
			break;
		}
	}
	if (prot_version || tpm_version || serial || cert_l2 || cert_fab || datablock)
		return 1;
	if (cert_l3)
		return 2;
	return 0;
}


static eString step1(int fd, int *error)
{
	unsigned int tag, len;
	unsigned char *val;
	unsigned char buf[3];

	unsigned long serial;
	int tpm_version, prot_version;

	buf[0] = TPMD_DT_PROTOCOL_VERSION;
	buf[1] = TPMD_DT_TPM_VERSION;
	buf[2] = TPMD_DT_SERIAL;
	send_cmd(fd, TPMD_CMD_GET_DATA, buf, 3);
	val = (unsigned char *)recv_cmd(fd, &tag, &len);
	assert(tag == TPMD_CMD_GET_DATA);
	int res = parse_data(val, len, &prot_version, &tpm_version, &serial, 0, 0, 0, 0);
	free(val);

	if(res)
	{
		*error=-4;//"data missing"
		return "";
	}
	
	if(prot_version != PROD_VERSION)
		*error=-5;//"tpmd version mismatch"

	eString ret;
	ret.sprintf("serial=%d&version=%d", serial, tpm_version);
	return ret;
}

/* NOTE: this is a modified base64 which uses -_ instead of +/ to avoid the need for escpaing + when using urlencode */
void base64_encode(char *dst, unsigned char *src, int len)
{
	const unsigned char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

	int cols = 0, bits = 0, char_count = 0;

	while (len--)
	{
		bits <<= 8;
		bits |= *src++;
		char_count++;
		if (char_count == 3)
		{
			*dst++ = alphabet[bits >> 18];
			*dst++ = alphabet[(bits >> 12) & 0x3f];
			*dst++ = alphabet[(bits >> 6) & 0x3f];
			*dst++ = alphabet[bits & 0x3f];
			bits = 0;
			char_count = 0;
		} 
	}
	if (char_count != 0)
	{
		bits <<= 24 - (8 * char_count);
		*dst++ = alphabet[bits >> 18];
		*dst++ = alphabet[(bits >> 12) & 0x3f];
		if (char_count == 1) 
		{
			*dst++ = '=';
			*dst++ = '=';
		} else
		{
			*dst++ = alphabet[(bits >> 6) & 0x3f];
			*dst++ = '=';
		}
	}
	*dst++ = 0;
}

int base64_decode(unsigned char *dst, char *src, int len)
{
	/* not using the modified form. */
	const unsigned char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	static char inalphabet[256], decoder[256];
	int i, bits, c, char_count, errors = 0;
	unsigned char *b = dst;

	for (i = (sizeof alphabet) - 1; i >= 0 ; i--) {
		inalphabet[alphabet[i]] = 1;
		decoder[alphabet[i]] = i;
	}

	char_count = 0;
	bits = 0;
	while (len--)
	{
		c = *src++;
		if (c == '=')
		  break;
		if (!inalphabet[c])
		  continue;
		bits |= decoder[c];
		char_count++;
		if (char_count == 4) {
			*dst++ = bits >> 16;
			*dst++ = (bits >> 8) & 0xff;
			*dst++ = (bits & 0xff);
			bits = 0;
			char_count = 0;
		} else {
			bits <<= 6;
		}
	}

	if (!len)
		return -1;

	switch (char_count) {
	  case 1:
	  	return -1;
	  case 2:
			*dst++ = bits >> 10;
			break;
	  case 3:
			*dst++ = bits >> 16;
			*dst++ = (bits >> 8) & 0xff;
			break;
	}
	return dst - b;
}

static eString step2(int fd, void *random, int random_len, int *error)
{
	unsigned int tag, len;
	unsigned char *val;

	unsigned char level2_cert[210];
	unsigned char level3_cert[210];
	unsigned char fab_ca_cert[210];
	unsigned char datablock_signed[128];
	unsigned char buf[7];

	unsigned long serial;

		/* gather required data */
	buf[0] = TPMD_DT_PROTOCOL_VERSION;
	buf[1] = TPMD_DT_TPM_VERSION;
	buf[2] = TPMD_DT_SERIAL;
	buf[3] = TPMD_DT_LEVEL2_CERT;
	buf[4] = TPMD_DT_LEVEL3_CERT;
	buf[5] = TPMD_DT_FAB_CA_CERT;
	buf[6] = TPMD_DT_DATABLOCK_SIGNED;
	send_cmd(fd, TPMD_CMD_GET_DATA, buf, 7);
	val = (unsigned char*)recv_cmd(fd, &tag, &len);
	assert(tag == TPMD_CMD_GET_DATA);
	int res = parse_data(val, len, 0, 0, &serial, level2_cert, level3_cert, fab_ca_cert, datablock_signed);
	free(val);

	if(res == 1)
	{
		*error=-4;//"data missing"
		return "";
	}

	send_cmd(fd, TPMD_CMD_COMPUTE_SIGNATURE, random, 8);
	val = (unsigned char*)recv_cmd(fd, &tag, &len);
	assert(tag == TPMD_CMD_COMPUTE_SIGNATURE);

	assert(random_len <= 128);
	assert(len <= 256);
	/* 3 certs + datablock_signed + random + sign */
	char response[BASE64_BUF(210) * 3 + BASE64_BUF(128) + BASE64_BUF(128) + BASE64_BUF(256) + 64];

	char *r = response;

	strcpy(response, "random=");
	r += strlen(r);

	base64_encode(r, (unsigned char*)random, random_len);
	r += strlen(r);

	strcpy(r, "&l2="); r+= strlen(r);
	base64_encode(r, level2_cert, 210);
	r += strlen(r);
	
	if (res == 0)
	{
		strcpy(r, "&l3="); r+= strlen(r);
		base64_encode(r, level3_cert, 210);
		r += strlen(r);
	}

	strcpy(r, "&fab="); r+= strlen(r);
	base64_encode(r, fab_ca_cert, 210);
	r += strlen(r);
	
	strcpy(r, "&data="); r+= strlen(r);
	base64_encode(r, datablock_signed, 128);
	r += strlen(r);
	
	strcpy(r, "&r="); r+= strlen(r);
	base64_encode(r, val, len);
	r += strlen(r);

	sprintf(r, "&serial=%d", serial); r+= strlen(r);

	free(val);
	return response;
}


//--------------------------------------------------------------------

eGenuineDreambox::eGenuineDreambox()
	: eWindow(0)
{
	cmove(ePoint(90, 140));
	cresize(eSize(550, 300));
	setText(_("Geniune Dreambox"));

	int fd=eSkin::getActive()->queryValue("fontsize", 20);

	le=new eLabel(this, RS_WRAP);
//	le->setProperty("align","center");
	le->setProperty("vcenter","");
	le->move(ePoint(5, 5));
	le->resize(eSize(clientrect.width()-10, clientrect.height()-90));
	le->setText(_("With this plugin you can verify the authenticity of your Dreambox.\n\n"
		"For additional information, please visit our website www.dream-multimedia-tv.de."));
	b_start=new eButton(this);
	b_start->move(ePoint(150, clientrect.height()-70));
	b_start->resize(eSize(200, fd+15));
	b_start->setShortcut("green");
	b_start->setShortcutPixmap("green");
	b_start->loadDeco();
	b_start->setText(_("start"));
	CONNECT(b_start->selected, eGenuineDreambox::start);

	step_timer = new eTimer(eApp);
	CONNECT( step_timer->timeout, eGenuineDreambox::nextStep);
}

eGenuineDreambox::~eGenuineDreambox()
{
	delete step_timer;
	if(sockfd) ::close(sockfd);
}

static eString clearEnd(eString value)
{
	while(1)
	{
		if(value[value.length()-1] == '\n')
			value.erase(value.length()-1);
		else if(value[value.length()-1] == '\r')
			value.erase(value.length()-1);
		else break;
	}
	return value;
}

void eGenuineDreambox::start()
{
	setStatus(_("Please wait...(Step 1)"));
	error=0;

	struct sockaddr_un addr;
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, TPMD_SOCKET);
	sockfd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (connect(sockfd, (const struct sockaddr *)&addr, SUN_LEN(&addr)))
	{
		setError(-7);
		return;
	}
	
	eString res = step1(sockfd,&error);
	if(error)
	{
		setError(error);
		return;
	}
	count=1;
	startDownload(DMM_URL + res);
}

void eGenuineDreambox::nextStep()
{
	setStatus(_("Please wait...(Step 2)"));
	value = clearEnd(value);
	
	unsigned char buf[128];
	int bytes = base64_decode(buf, (char*)value.c_str(), value.length());
	
	if (bytes < 0)
	{
		setError(-6);
		return;
	}

	eString res=step2(sockfd, buf, bytes, &error);
	if(error)
	{
		setError(error);
		return;
	}
	count=2;
	startDownload(DMM_URL + res);
}

void eGenuineDreambox::setStatus(const eString &string)
{
	le->setText(string);
}

void eGenuineDreambox::startDownload(const eString &url)
{
	value="";
	//printf("url=%s\n",url.c_str());
	http=eHTTPConnection::doRequest(url.c_str(), eApp, &error);
	if (!http)
	{
		infoTransferDone(error);
	} else
	{
		CONNECT(http->transferDone, eGenuineDreambox::infoTransferDone);
		CONNECT(http->createDataSource, eGenuineDreambox::createInfoDataSink);
		//http->request = "POST";
		//http->local_header["Content-Type"]="application/x-www-form-urlencoded";
		//http->local_header["Content-Length"]="1243";
		
		http->start();
	}
}

void eGenuineDreambox::infoTransferDone(int err)
{
	if ((!err) && http && (http->code == 200))
	{
		//eDebug("value='%s'",value.c_str());
		if(count==1 && value.length()>2)
		{
			step_timer->start(300, true);
		}
		else	::close(sockfd);

		if(count==2)
		{
			if(value.length()>=13 && value[0] == '+')
			{
				value = clearEnd(value);
				if(value.length()==13)
				{
					eString text = _("Authentication code: ");
					eString code = value.substr(1, 4);
					code += " - " + value.substr(5, 4);
					code += " - " + value.substr(9);
					text += code;
					text += "\n\n";
					text += _("With this code you can check the authenticity of your Dreambox.\n\n"
						"Please visit our website and follow the instructions.\n\n"
						"Alternatively you can call our customer service hotline.");
					setStatus(text);
					b_start->setText(_("restart"));
				}
				else setError(-8);
			}
			else setError(-8);
		}
	}
	else
	{
		if (err || http->code !=200)
			setError(err);
	}
	http=0;
}

void eGenuineDreambox::setError(int err)
{
	eString errmsg;
	switch (err)
	{
	case 0:
		if (http && http->code != 200)
		{
			errmsg = _("Server error");
			errmsg += " ";
			errmsg += eString().setNum(http->code);
			errmsg += " ";
			errmsg += http->code_descr;
			errmsg += ".";
			errmsg += _("Please report!");
		}
		break;
	case -2:
		errmsg=_("Can't resolve hostname. Please check your network!");
		break;
	case -3:
		errmsg=_("Can't connect to server. Please check your network!");
		break;
	case -4:
		errmsg=_("Internal error (code1). Please report!");
		break;
	case -5:
		errmsg=_("Security service not running.");
		break;
	case -6:
		errmsg=_("Can't read data from server.");
		break;
	case -7:
		errmsg=_("Can't connect to security service.");
		break;
	case -8:
		errmsg=_("Invalid response from server. Please report!");
		break;
	default:
		errmsg.sprintf(_("Unknown error %d. Please report!"), err);
	}
	setStatus(errmsg);
}

eHTTPDataSource *eGenuineDreambox::createInfoDataSink(eHTTPConnection *conn)
{
	return datainfo=new eHTTPDownloadInfo(conn, &value);
}

eHTTPDownloadInfo::eHTTPDownloadInfo(eHTTPConnection *c, eString *value): eHTTPDataSource(c), value(value), error(0)
{
}

void eHTTPDownloadInfo::haveData(void *data, int len)
{
	if((!error) && len)
	{
		*value = std::string((char*)data,len);
#if TPMDEBUG
		eDebug("haveData=%s",value->c_str());
#endif
	}
}

//--------------------------------------------------------------------

extern "C" int plugin_exec( PluginParam *par );

int plugin_exec( PluginParam *par )
{
	eGenuineDreambox dlg;
	dlg.show();
	dlg.exec();
	dlg.hide();
	return 0;
}
