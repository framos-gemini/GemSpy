from dataclasses import dataclass, field
@dataclass
class Code:
   ECA_NORMAL:		int = 0x0001
   ECA_MAXIOC:		int = 0x0010
   ECA_UKNHOST:		int = 0x0018
   ECA_UKNSERV:		int = 0x0026
   ECA_SOCK:		int = 0x0034
   ECA_CONN:		int = 0x0040
   ECA_ALLOCMEM:	int = 0x0048
   ECA_UKNCHAN:		int = 0x0056
   ECA_UKNFIELD:	int = 0x0064
   ECA_TOLARGE:		int = 0x0072
   ECA_TIMEOUT:		int = 0x0080
   ECA_NOSUPPORT:	int = 0x0088
   ECA_STRTOBIG:	int = 0x0096
   ECA_DISCONNCHID:	int = 0x00106
   ECA_BADTYPE:		int = 0x00114
   ECA_CHIDNOTFND:	int = 0x00123
   ECA_CHIDRETRY:	int = 0x00131
   ECA_INTERNAL:	int = 0x00142
   ECA_DBLCLFAIL:	int = 0x00144
   ECA_GETFAIL:		int = 0x00152
   ECA_PUTFAIL:		int = 0x00160
   ECA_ADDFAIL:		int = 0x00168
   ECA_BADCOUNT:	int = 0x00176
   ECA_BADSTR:		int = 0x00186
   ECA_DISCONN:		int = 0x00192
   ECA_DBLCHNL:		int = 0x00200
   ECA_EVDISALLOW:	int = 0x00210
   ECA_BUILDGET:	int = 0x00216
   ECA_NEEDSFP:		int = 0x00224
   ECA_OVEVFAIL:	int = 0x00232
   ECA_BADMONID:	int = 0x00242
   ECA_NEWADDR:		int = 0x00248
   ECA_NEWCONN:		int = 0x00259
   ECA_NOCACTX:		int = 0x00264
   ECA_DEFUNCT:		int = 0x00278
   ECA_EMPTYSTR:	int = 0x00280
   ECA_NOREPEATER:	int = 0x00288
   ECA_NOCHANMSG:	int = 0x00296
   ECA_DLCKREST:	int = 0x00304
   ECA_SERVBEHIND:	int = 0x00312
   ECA_NOCAST:		int = 0x00320
   ECA_BADMASK:		int = 0x00330
   ECA_IODONE:		int = 0x00339
   ECA_IOINPROGRESS:	int = 0x00347
   ECA_BADSYNCGRP:	int = 0x00354
   ECA_PUTCBINPROG:	int = 0x00362
   ECA_NORDACCESS:	int = 0x00368
   ECA_NOWTACCESS:	int = 0x00376
   ECA_ANACHRONISM:	int = 0x00386
   ECA_NOSEARCHADDR:	int = 0x00392
   ECA_NOCONVERT:	int = 0x00400
   ECA_BADCHID:		int = 0x00410
   ECA_BADFUNCPTR:	int = 0x00418
   ECA_ISATTACHED:	int = 0x00424
   ECA_UNAVAILINSERV:	int = 0x00432
   ECA_CHANDESTROY:	int = 0x00440
   ECA_BADPRIORITY:	int = 0x00450
   ECA_NOTTHREADED:	int = 0x00458
   ECA_16KARRAYCLIENT:	int = 0x00464
   ECA_CONNSEQTMO:	int = 0x00472
