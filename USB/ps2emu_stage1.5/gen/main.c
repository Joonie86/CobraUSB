#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

typedef struct _List
{
	struct _List *next;
	int index;
	const char *name;
} List;

uint8_t code[65536];

static uint8_t 	ACALL, ADD1,  ADD2,  ADD3,  ADD4,  ADDC1, ADDC2, ADDC3, ADDC4,
		AJMP,  ANL1,  ANL2,  ANL3,  ANL4,  ANL5,  ANL6,  ANL7,  ANL8, 
		CJNE1, CJNE2, CJNE3, CJNE4, CLR1,  CLR2,  CLR3,  CPL1,  CPL2,  
		CPL3,  DA,    DEC1,  DEC2,  DEC3,  DEC4,  DIV,   DJNZ1, DJNZ2, 
		INC1,  INC2,  INC3,  INC4,  INC5,  JB,    JBC,   JC,    JMP,   
		JNB,   JNC,   JNZ,   JZ,    LCALL, LJMP,  MOV1,  MOV2,  MOV3,  
		MOV4,  MOV5,  MOV6,  MOV7,  MOV8,  MOV9,  MOV10, MOV11, MOV12, 
		MOV13, MOV14, MOV15, MOV16, MOV17, MOV18, MOVC1, MOVC2, MOVX1, 
		MOVX2, MOVX3, MOVX4, MUL,   ORL1,  ORL2,  ORL3,  ORL4,  
		ORL5,  ORL6,  ORL7,  ORL8,  POP,   PUSH,  RET,    RL,    
		RLC,   RR,    RRC,   SETB1, SETB2, SJMP,  SUBB1, SUBB2, SUBB3, 
		SUBB4, SWAP,  XCH1,  XCH2,  XCH3,  XCHD,  XRL1,  XRL2,  XRL3,  
		XRL4,  XRL5,  XRL6; 
		
static uint8_t ANL2_X, ANL4_X, ANL5_X, ANL6_X1, ANL6_X2, ANL7_X, ANL8_X, ORL2_X, ORL4_X, ORL5_X,
	       ORL6_X1, ORL6_X2, ORL7_X, ORL8_X, XRL2_X, XRL4_X, XRL5_X, XRL6_X1, XRL6_X2, CLR3_X,
	       SETB2_X, CPL3_X, XCH2_X, LCALL_X1, LCALL_X2, ACALL_X, CJNE1_X1, CJNE1_X2, CJNE2_X1,
	       CJNE2_X2, CJNE3_X1, CJNE3_X2, CJNE4_X1, CJNE4_X2, DEC3_X, INC3_X, DJNZ1_X, DJNZ2_X1,
	       DJNZ2_X2, POP_X, PUSH_X, JB_X1, JB_X2, JBC_X1, JBC_X2, JC_X, JNB_X1, JNB_X2, JNC_X,
	       JNZ_X, JZ_X, AJMP_X, LJMP_X1, LJMP_X2, SJMP_X, MOV2_X, MOV4_X, MOV6_X, MOV7_X, MOV8_X,
	       MOV9_X, MOV10_X1, MOV10_X2, MOV11_X, MOV12_X1, MOV12_X2, MOV14_X, MOV15_X, MOV16_X,
	       MOV17_X, MOV18_X1, MOV18_X2, ADD2_X, ADD4_X, ADDC2_X, ADDC4_X, SUBB2_X, SUBB4_X;


#define N1	73
#define N2	18
#define N3	16
#define N4	2

uint8_t group1_opcodes[N1] = 
{
	0x25, 0x24, 0x35, 0x34, 0x55, 0x54, 0x52, 0x53,
	0x82, 0xB0, 0xB5, 0xB4, 0xE4, 0xC3, 0xC2, 0xF4,
	0xB3, 0xB2, 0xD4, 0x14, 0x84, 0xD5, 0x04, 0x05,
	0xA3, 0x20, 0x10, 0x40, 0x73, 0x30, 0x50, 0x70,
	0x60, 0x12, 0x02, 0xE5, 0x74, 0xF5, 0x85, 0x75,
	0xA2, 0x92, 0x90, 0x93, 0x83, 0xE0, 0xF0, 0xA4,
	0x45, 0x44, 0x42, 0x43, 0x72, 0xA0, 0xD0, 0xC0,
	0x22, 0x15, 0x23, 0x33, 0x03, 0x13, 0xD3, 0xD2,
	0x80, 0x95, 0x94, 0xC4, 0xC5, 0x65, 0x64, 0x62,
	0x63
};

uint8_t group2_opcodes[N2] =
{
	0x26, 0x36, 0x56, 0xB6, 0x16, 0x06, 0xE6, 0x86,
	0xF6, 0xA6, 0x76, 0xE2, 0xF2, 0x46, 0x96, 0xC6,
	0xD6, 0x66
};

uint8_t group3_opcodes[N3] =
{
	0x28, 0x38, 0x58, 0xB8, 0x18, 0xD8, 0x08, 0xE8, 
	0xF8, 0xA8, 0x78, 0x88, 0x48, 0x98, 0x68, 0xC8
};

uint8_t group4_opcodes[N4] =
{
	0x11, 0x01
};

static List *ListAppend(List *list, int index)
{
	if (list == NULL)
	{
		list = malloc(sizeof(List));			
	}
	else
	{
		while (list->next)
			list = list->next;
		
		list->next = malloc(sizeof(List));
		list = list->next;
	}
	
	list->next = NULL;
	list->index = index;
	return list;
}

static List *ListAppend2(List *list, int index, const char *name)
{
	if (list == NULL)
	{
		list = malloc(sizeof(List));			
	}
	else
	{
		while (list->next)
			list = list->next;
		
		list->next = malloc(sizeof(List));
		list = list->next;
	}
	
	list->next = NULL;
	list->index = index;
	list->name = name;
	return list;
}

static int GetListLength(List *list)
{
	int n = 0;
	
	while (list)
	{
		n++;
		list = list->next;
	}
	
	return n;
}

static uint8_t PopRandomOpcode1(List **plist)
{
	List *list = *plist;
	List *prev = NULL;
	int len = GetListLength(list);
	
	if (len == 0)
		printf("Called with 0!!!\n");
	
	int rnd = rand() % len;
	
	for (int i = 0; i < rnd; i++)
	{
		prev = list;
		list = list->next;
	}
	
	uint8_t ret = group1_opcodes[list->index];
	
	if (rnd == 0)
	{
		*plist = list->next;
		free(list);
	}
	else
	{
		prev->next = list->next;
		free(list);
	}
	
	return ret;
}

static uint8_t PopRandomOpcode2(List **plist)
{
	List *list = *plist;
	List *prev = NULL;
	int len = GetListLength(list);
	
	if (len == 0)
		printf("Called with 0!!!\n");
	
	int rnd = rand() % len;
	
	for (int i = 0; i < rnd; i++)
	{
		prev = list;
		list = list->next;
	}
	
	uint8_t ret = group2_opcodes[list->index];
	
	if (rnd == 0)
	{
		*plist = list->next;
		free(list);
	}
	else
	{
		prev->next = list->next;
		free(list);
	}
	
	return ret;
}

static uint8_t PopRandomOpcode3(List **plist)
{
	List *list = *plist;
	List *prev = NULL;
	int len = GetListLength(list);
	
	if (len == 0)
		printf("Called with 0!!!\n");
	
	int rnd = rand() % len;
	
	for (int i = 0; i < rnd; i++)
	{
		prev = list;
		list = list->next;
	}
	
	uint8_t ret = group3_opcodes[list->index];
	
	if (rnd == 0)
	{
		*plist = list->next;
		free(list);
	}
	else
	{
		prev->next = list->next;
		free(list);
	}
	
	return ret;
}

static uint8_t PopRandomOpcode4(List **plist)
{
	List *list = *plist;
	List *prev = NULL;
	int len = GetListLength(list);
	
	if (len == 0)
		printf("Called with 0!!!\n");
	
	int rnd = rand() % len;
	
	for (int i = 0; i < rnd; i++)
	{
		prev = list;
		list = list->next;
	}
	
	uint8_t ret = group4_opcodes[list->index];
	
	if (rnd == 0)
	{
		*plist = list->next;
		free(list);
	}
	else
	{
		prev->next = list->next;
		free(list);
	}
	
	return ret;
}

const char *PopRandomOpcode(List **plist, uint8_t *opcode)
{
	List *list = *plist;
	List *prev = NULL;
	int len = GetListLength(list);
	
	if (len == 0)
		printf("Called with 0!!!\n");
	
	int rnd = rand() % len;
	
	for (int i = 0; i < rnd; i++)
	{
		prev = list;
		list = list->next;
	}
	
	*opcode = list->index;
	const char *ret = list->name;
	
	if (rnd == 0)
	{
		*plist = list->next;
		free(list);
	}
	else
	{
		prev->next = list->next;
		free(list);
	}
	
	return ret;
}
		
static void AssignOpcodes(FILE *f)
{
	List *group1 = ListAppend(NULL, 0);
	int i;
	
	for (i = 1; i < N1; i++)
		ListAppend(group1, i);
	
	ADD2 = PopRandomOpcode1(&group1);
	ADD4 = PopRandomOpcode1(&group1);
	ADDC2 = PopRandomOpcode1(&group1);
	ADDC4 = PopRandomOpcode1(&group1);
	ANL2 = PopRandomOpcode1(&group1);
	ANL4 = PopRandomOpcode1(&group1);
	ANL5 = PopRandomOpcode1(&group1);
	ANL6 = PopRandomOpcode1(&group1);
	ANL7 = PopRandomOpcode1(&group1);
	ANL8 = PopRandomOpcode1(&group1);
	CJNE1 = PopRandomOpcode1(&group1);
	CJNE2 = PopRandomOpcode1(&group1);
	CLR1 = PopRandomOpcode1(&group1);
	CLR2 = PopRandomOpcode1(&group1);
	CLR3 = PopRandomOpcode1(&group1);
	CPL1 = PopRandomOpcode1(&group1);
	CPL2 = PopRandomOpcode1(&group1);
	CPL3 = PopRandomOpcode1(&group1);
	DA = PopRandomOpcode1(&group1);
	DEC1 = PopRandomOpcode1(&group1);
	DEC3 = PopRandomOpcode1(&group1);
	DIV = PopRandomOpcode1(&group1);
	DJNZ2 = PopRandomOpcode1(&group1);
	INC1 = PopRandomOpcode1(&group1);
	INC3 = PopRandomOpcode1(&group1);
	INC5 = PopRandomOpcode1(&group1);
	JB = PopRandomOpcode1(&group1);
	JBC = PopRandomOpcode1(&group1);
	JC = PopRandomOpcode1(&group1);
	JMP = PopRandomOpcode1(&group1);
	JNB = PopRandomOpcode1(&group1);
	JNC = PopRandomOpcode1(&group1);
	JNZ = PopRandomOpcode1(&group1);
	JZ = PopRandomOpcode1(&group1);
	LCALL = PopRandomOpcode1(&group1);
	LJMP = PopRandomOpcode1(&group1);
	MOV2 = PopRandomOpcode1(&group1);
	MOV4 = PopRandomOpcode1(&group1);
	MOV8 = PopRandomOpcode1(&group1);
	MOV10 = PopRandomOpcode1(&group1);
	MOV12 = PopRandomOpcode1(&group1);
	MOV16 = PopRandomOpcode1(&group1);
	MOV17 = PopRandomOpcode1(&group1);
	MOV18 = PopRandomOpcode1(&group1);
	MOVC1 = PopRandomOpcode1(&group1);
	MOVC2 = PopRandomOpcode1(&group1);
	MOVX2 = PopRandomOpcode1(&group1);
	MOVX4 = PopRandomOpcode1(&group1);
	MUL = PopRandomOpcode1(&group1);
	ORL2 = PopRandomOpcode1(&group1);
	ORL4 = PopRandomOpcode1(&group1);
	ORL5 = PopRandomOpcode1(&group1);
	ORL6 = PopRandomOpcode1(&group1);
	ORL7 = PopRandomOpcode1(&group1);
	ORL8 = PopRandomOpcode1(&group1);
	POP = PopRandomOpcode1(&group1);
	PUSH = PopRandomOpcode1(&group1);
	RET = PopRandomOpcode1(&group1);
	RL = PopRandomOpcode1(&group1);
	RLC = PopRandomOpcode1(&group1);
	RR = PopRandomOpcode1(&group1);
	RRC = PopRandomOpcode1(&group1);
	SETB1 = PopRandomOpcode1(&group1);
	SETB2 = PopRandomOpcode1(&group1);
	SJMP = PopRandomOpcode1(&group1);
	SUBB2 = PopRandomOpcode1(&group1);
	SUBB4 = PopRandomOpcode1(&group1);
	SWAP = PopRandomOpcode1(&group1);
	XCH2 = PopRandomOpcode1(&group1);
	XRL2 = PopRandomOpcode1(&group1);
	XRL4 = PopRandomOpcode1(&group1);
	XRL5 = PopRandomOpcode1(&group1);
	XRL6 = PopRandomOpcode1(&group1);
	
	group1 = ListAppend(NULL, 0);
	for (i = 1; i < N2; i++)
		ListAppend(group1, i);
	
	ADD3 = PopRandomOpcode2(&group1);
	ADDC3 = PopRandomOpcode2(&group1);
	ANL3 = PopRandomOpcode2(&group1);
	CJNE4 = PopRandomOpcode2(&group1);
	DEC4 = PopRandomOpcode2(&group1);
	INC4 = PopRandomOpcode2(&group1);
	MOV3 = PopRandomOpcode2(&group1);
	MOV11 = PopRandomOpcode2(&group1);
	MOV13 = PopRandomOpcode2(&group1);
	MOV14 = PopRandomOpcode2(&group1);
	MOV15 = PopRandomOpcode2(&group1);
	MOVX1 = PopRandomOpcode2(&group1);
	MOVX3 = PopRandomOpcode2(&group1);
	ORL3 = PopRandomOpcode2(&group1);
	SUBB3 = PopRandomOpcode2(&group1);
	XCH3 = PopRandomOpcode2(&group1);
	XCHD = PopRandomOpcode2(&group1);
	XRL3 = PopRandomOpcode2(&group1);
	
	
	group1 = ListAppend(NULL, 0);
	for (i = 1; i < N3; i++)
		ListAppend(group1, i);
	
	ADD1 = PopRandomOpcode3(&group1);
	ADDC1 = PopRandomOpcode3(&group1);
	ANL1 = PopRandomOpcode3(&group1);
	CJNE3 = PopRandomOpcode3(&group1);
	DEC2 = PopRandomOpcode3(&group1);
	DJNZ1 = PopRandomOpcode3(&group1);
	INC2 = PopRandomOpcode3(&group1);
	MOV1 = PopRandomOpcode3(&group1);
	MOV5 = PopRandomOpcode3(&group1);
	MOV6 = PopRandomOpcode3(&group1);
	MOV7 = PopRandomOpcode3(&group1);
	MOV9 = PopRandomOpcode3(&group1);
	ORL1 = PopRandomOpcode3(&group1);
	SUBB1 = PopRandomOpcode3(&group1);
	XRL1 = PopRandomOpcode3(&group1);
	XCH1 = PopRandomOpcode3(&group1);
	
	group1 = ListAppend(NULL, 0);
	for (i = 1; i < N4; i++)
		ListAppend(group1, i);
	
	ACALL = PopRandomOpcode4(&group1);
	AJMP = PopRandomOpcode4(&group1);
	
	ANL2_X = rand();
	ANL4_X = rand();
	ANL5_X = rand();
	ANL6_X1 = rand();
	ANL6_X2 = rand();
	ANL7_X = rand();
	ANL8_X = rand();
	ORL2_X = rand();
	ORL4_X = rand();
	ORL5_X = rand();
	ORL6_X1 = rand();
	ORL6_X2 = rand();
	ORL7_X = rand();
	ORL8_X = rand();
	XRL2_X = rand();
	XRL4_X = rand();
	XRL5_X = rand();
	XRL6_X1 = rand();
	XRL6_X2 = rand();
	CLR3_X = rand();
	SETB2_X = rand();
	CPL3_X = rand();
	XCH2_X = rand();
	LCALL_X1 = rand();
	LCALL_X2 = rand();
	ACALL_X = rand();
	CJNE1_X1 = rand();
	CJNE1_X2  = rand();
	CJNE2_X1 = rand();
	CJNE2_X2 = rand();
	CJNE3_X1 = rand();
	CJNE3_X2 = rand();
	CJNE4_X1 = rand();
	CJNE4_X2 = rand();
	DEC3_X = rand();
	INC3_X = rand();
	DJNZ1_X = rand();
	DJNZ2_X1 = rand();
	DJNZ2_X2 = rand();
	POP_X = rand();
	PUSH_X = rand();
	JB_X1 = rand();
	JB_X2 = rand();
	JBC_X1 = rand();
	JBC_X2 = rand();
	JC_X = rand();
	JNB_X1 = rand();
	JNB_X2 = rand();
	JNC_X = rand();
	JNZ_X = rand();
	JZ_X = rand();
	AJMP_X = rand();
	LJMP_X1 = rand();
	LJMP_X2 = rand();
	SJMP_X = rand();
	MOV2_X = rand();
	MOV4_X = rand();
	MOV6_X = rand();
	MOV7_X = rand();
	MOV8_X = rand();
	MOV9_X = rand();
	MOV10_X1 = rand();
	MOV10_X2 = rand();
	MOV11_X = rand();
	MOV12_X1 = rand();
	MOV12_X2 = rand();
	MOV14_X = rand();
	MOV15_X = rand();
	MOV16_X = rand();
	MOV17_X = rand();
	MOV18_X1 = rand();
	MOV18_X2 = rand();
	ADD2_X = rand();
	ADD4_X = rand();
	ADDC2_X = rand();
	ADDC4_X = rand();
	SUBB2_X = rand();
	SUBB4_X = rand();
	
	group1 = ListAppend2(NULL, ADD2, "ADD2");
	ListAppend2(group1, ADD4, "ADD4");
	ListAppend2(group1, ADDC2, "ADDC2");
	ListAppend2(group1, ADDC4, "ADDC4");
	ListAppend2(group1, ANL2, "ANL2");
	ListAppend2(group1, ANL4, "ANL4");
	ListAppend2(group1, ANL5, "ANL5");
	ListAppend2(group1, ANL6, "ANL6");
	ListAppend2(group1, ANL7, "ANL7");
	ListAppend2(group1, ANL8, "ANL8");
	ListAppend2(group1, CJNE1, "CJNE1");
	ListAppend2(group1, CJNE2, "CJNE2");
	ListAppend2(group1, CLR1, "CLR1");
	ListAppend2(group1, CLR2, "CLR2");
	ListAppend2(group1, CLR3, "CLR3");
	ListAppend2(group1, CPL1, "CPL1");
	ListAppend2(group1, CPL2, "CPL2");
	ListAppend2(group1, CPL3, "CPL3");
	ListAppend2(group1, DA, "DA");
	ListAppend2(group1, DEC1, "DEC1");
	ListAppend2(group1, DEC3, "DEC3");
	ListAppend2(group1, DIV, "DIV");
	ListAppend2(group1, DJNZ2, "DJNZ2");
	ListAppend2(group1, INC1, "INC1");
	ListAppend2(group1, INC3, "INC3");
	ListAppend2(group1, INC5, "INC5");
	ListAppend2(group1, JB, "JB");
	ListAppend2(group1, JBC, "JBC");
	ListAppend2(group1, JC, "JC");
	ListAppend2(group1, JMP, "JMP");
	ListAppend2(group1, JNB, "JNB");
	ListAppend2(group1, JNC, "JNC");
	ListAppend2(group1, JNZ, "JNZ");
	ListAppend2(group1, JZ, "JZ");
	ListAppend2(group1, LCALL, "LCALL");
	ListAppend2(group1, LJMP, "LJMP");
	ListAppend2(group1, MOV2, "MOV2");
	ListAppend2(group1, MOV4, "MOV4");
	ListAppend2(group1, MOV8, "MOV8");
	ListAppend2(group1, MOV10, "MOV10");
	ListAppend2(group1, MOV12, "MOV12");
	ListAppend2(group1, MOV16, "MOV16");
	ListAppend2(group1, MOV17, "MOV17");
	ListAppend2(group1, MOV18, "MOV18");
	ListAppend2(group1, MOVC1, "MOVC1");
	ListAppend2(group1, MOVC2, "MOVC2");
	ListAppend2(group1, MOVX2, "MOVX2");
	ListAppend2(group1, MOVX4, "MOVX4");
	ListAppend2(group1, MUL, "MUL");
	ListAppend2(group1, ORL2, "ORL2");
	ListAppend2(group1, ORL4, "ORL4");
	ListAppend2(group1, ORL5, "ORL5");
	ListAppend2(group1, ORL6, "ORL6");
	ListAppend2(group1, ORL7, "ORL7");
	ListAppend2(group1, ORL8, "ORL8");
	ListAppend2(group1, POP, "POP");
	ListAppend2(group1, PUSH, "PUSH");
	ListAppend2(group1, RET, "RET");
	ListAppend2(group1, RL, "RL");
	ListAppend2(group1, RLC, "RLC");
	ListAppend2(group1, RR, "RR");
	ListAppend2(group1, RRC, "RRC");
	ListAppend2(group1, SETB1, "SETB1");
	ListAppend2(group1, SETB2, "SETB2");
	ListAppend2(group1, SJMP, "SJMP");
	ListAppend2(group1, SUBB2, "SUBB2");
	ListAppend2(group1, SUBB4, "SUBB4");
	ListAppend2(group1, SWAP, "SWAP");
	ListAppend2(group1, XCH2, "XCH2");
	ListAppend2(group1, XRL2, "XRL2");
	ListAppend2(group1, XRL4, "XRL4");
	ListAppend2(group1, XRL5, "XRL5");
	ListAppend2(group1, XRL6, "XRL6");
	ListAppend2(group1, ADD3, "ADD3");
	ListAppend2(group1, ADDC3, "ADDC3");
	ListAppend2(group1, ANL3, "ANL3");
	ListAppend2(group1, CJNE4, "CJNE4");
	ListAppend2(group1, DEC4, "DEC4");
	ListAppend2(group1, INC4, "INC4");
	ListAppend2(group1, MOV3, "MOV3");
	ListAppend2(group1, MOV11, "MOV11");
	ListAppend2(group1, MOV13, "MOV13");
	ListAppend2(group1, MOV14, "MOV14");
	ListAppend2(group1, MOV15, "MOV15");
	ListAppend2(group1, MOVX1, "MOVX1");
	ListAppend2(group1, MOVX3, "MOVX3");
	ListAppend2(group1, ORL3, "ORL3");
	ListAppend2(group1, SUBB3, "SUBB3");
	ListAppend2(group1, XCH3, "XCH3");
	ListAppend2(group1, XCHD, "XCHD");
	ListAppend2(group1, XRL3, "XRL3");
	ListAppend2(group1, ADD1, "ADD1");
	ListAppend2(group1, ADDC1, "ADDC1");
	ListAppend2(group1, ANL1, "ANL1");
	ListAppend2(group1, CJNE3, "CJNE3");
	ListAppend2(group1, DEC2, "DEC2");
	ListAppend2(group1, DJNZ1, "DJNZ1");
	ListAppend2(group1, INC2, "INC2");
	ListAppend2(group1, MOV1, "MOV1");
	ListAppend2(group1, MOV5, "MOV5");
	ListAppend2(group1, MOV6, "MOV6");
	ListAppend2(group1, MOV7, "MOV7");
	ListAppend2(group1, MOV9, "MOV9");
	ListAppend2(group1, ORL1, "ORL1");
	ListAppend2(group1, SUBB1, "SUBB1");
	ListAppend2(group1, XRL1, "XRL1");
	ListAppend2(group1, XCH1, "XCH1");
	ListAppend2(group1, ACALL, "ACALL");
	ListAppend2(group1, AJMP, "AJMP");
	ListAppend2(group1, ANL2_X, "ANL2_X");
	ListAppend2(group1, ANL4_X, "ANL4_X");
	ListAppend2(group1, ANL5_X, "ANL5_X");
	ListAppend2(group1, ANL6_X1, "ANL6_X1");
	ListAppend2(group1, ANL6_X2, "ANL6_X2");
	ListAppend2(group1, ANL7_X, "ANL7_X");
	ListAppend2(group1, ANL8_X, "ANL8_X");
	ListAppend2(group1, ORL2_X, "ORL2_X");
	ListAppend2(group1, ORL4_X, "ORL4_X");
	ListAppend2(group1, ORL5_X, "ORL5_X");
	ListAppend2(group1, ORL6_X1,"ORL6_X1");
	ListAppend2(group1, ORL6_X2, "ORL6_X2");
	ListAppend2(group1, ORL7_X, "ORL7_X");
	ListAppend2(group1, ORL8_X, "ORL8_X");
	ListAppend2(group1, XRL2_X, "XRL2_X");
	ListAppend2(group1, XRL4_X, "XRL4_X");
	ListAppend2(group1, XRL5_X, "XRL5_X");
	ListAppend2(group1, XRL6_X1, "XRL6_X1");
	ListAppend2(group1, XRL6_X2, "XRL6_X2");
	ListAppend2(group1, CLR3_X, "CLR3_X");
	ListAppend2(group1, SETB2_X, "SETB2_X");
	ListAppend2(group1, CPL3_X, "CPL3_X");
	ListAppend2(group1, XCH2_X, "XCH2_X");
	ListAppend2(group1, LCALL_X1, "LCALL_X1");
	ListAppend2(group1, LCALL_X2, "LCALL_X2");
	ListAppend2(group1, ACALL_X, "ACALL_X");
	ListAppend2(group1, CJNE1_X1, "CJNE1_X1");
	ListAppend2(group1, CJNE1_X2, "CJNE1_X2");
	ListAppend2(group1, CJNE2_X1, "CJNE2_X1");
	ListAppend2(group1, CJNE2_X2, "CJNE2_X2");
	ListAppend2(group1, CJNE3_X1, "CJNE3_X1");
	ListAppend2(group1, CJNE3_X2, "CJNE3_X2");
	ListAppend2(group1, CJNE4_X1, "CJNE4_X1");
	ListAppend2(group1, CJNE4_X2, "CJNE4_X2");
	ListAppend2(group1, DEC3_X, "DEC3_X");
	ListAppend2(group1, INC3_X, "INC3_X");
	ListAppend2(group1, DJNZ1_X, "DJNZ1_X");
	ListAppend2(group1, DJNZ2_X1, "DJNZ2_X1");
	ListAppend2(group1, DJNZ2_X2, "DJNZ2_X2");
	ListAppend2(group1, POP_X, "POP_X");
	ListAppend2(group1, PUSH_X, "PUSH_X");
	ListAppend2(group1, JB_X1, "JB_X1");
	ListAppend2(group1, JB_X2, "JB_X2");
	ListAppend2(group1, JBC_X1, "JBC_X1");
	ListAppend2(group1, JBC_X2, "JBC_X2");
	ListAppend2(group1, JC_X, "JC_X");
	ListAppend2(group1, JNB_X1, "JNB_X1");
	ListAppend2(group1, JNB_X2, "JNB_X2");
	ListAppend2(group1, JNC_X, "JNC_X");
	ListAppend2(group1, JNZ_X, "JNZ_X");
	ListAppend2(group1, JZ_X, "JZ_X");
	ListAppend2(group1, AJMP_X, "AJMP_X");
	ListAppend2(group1, LJMP_X1, "LJMP_X1");
	ListAppend2(group1, LJMP_X2, "LJMP_X2");
	ListAppend2(group1, SJMP_X, "SJMP_X");
	ListAppend2(group1, MOV2_X, "MOV2_X");
	ListAppend2(group1, MOV4_X, "MOV4_X");
	ListAppend2(group1, MOV6_X, "MOV6_X");
	ListAppend2(group1, MOV7_X, "MOV7_X");
	ListAppend2(group1, MOV8_X, "MOV8_X");
	ListAppend2(group1, MOV9_X, "MOV9_X");
	ListAppend2(group1, MOV10_X1, "MOV10_X1");
	ListAppend2(group1, MOV10_X2, "MOV10_X2");
	ListAppend2(group1, MOV11_X, "MOV11_X");
	ListAppend2(group1, MOV12_X1, "MOV12_X1");
	ListAppend2(group1, MOV12_X2, "MOV12_X2");
	ListAppend2(group1, MOV14_X, "MOV14_X");
	ListAppend2(group1, MOV15_X, "MOV15_X");
	ListAppend2(group1, MOV16_X, "MOV16_X");
	ListAppend2(group1, MOV17_X, "MOV17_X");
	ListAppend2(group1, MOV18_X1, "MOV18_X1");
	ListAppend2(group1, MOV18_X2, "MOV18_X2");
	ListAppend2(group1, ADD2_X, "ADD2_X");
	ListAppend2(group1, ADD4_X, "ADD4_X");
	ListAppend2(group1, ADDC2_X, "ADDC2_X");
	ListAppend2(group1, ADDC4_X, "ADDC4_X");
	ListAppend2(group1, SUBB2_X, "SUBB2_X");
	ListAppend2(group1, SUBB4_X, "SUBB4_X");
	
	int n = GetListLength(group1);
	
	for (i = 0; i < n; i++)
	{
		uint8_t opcode;
		const char *name = PopRandomOpcode(&group1, &opcode);
		
		fprintf(f, "static uint8_t %s = 0x%02X;\n", name, opcode);
	}
}

int Decode(const unsigned char IR, uint8_t PC) 
{    
    // BBBBBBBB
    switch( IR ) {
	case 0x25:
	    return ADD2;
	case 0x24:
	    return ADD4;
	case 0x35:
	    return ADDC2;
	case 0x34:
	    return ADDC4;
	case 0x55:
	    return ANL2;
	case 0x54:
	    return ANL4;
	case 0x52:
	    return ANL5;
	case 0x53:
	    return ANL6;
	case 0x82:
	    return ANL7;
	case 0xB0:
	    return ANL8;
	case 0xB5:
	    return CJNE1;
	case 0xB4:
	    return CJNE2;
	case 0xE4:
	    return CLR1;
	case 0xC3:
	    return CLR2;
	case 0xC2:
	    return CLR3;
	case 0xF4:
	    return CPL1;
	case 0xB3:
	    return CPL2;
	case 0xB2:
	    return CPL3;
	case 0xD4:
	    return DA;
	case 0x14:
	    return DEC1;
	case 0x15:
	    return DEC3;
	case 0x84:
	    return DIV;
	case 0xD5:
	    return DJNZ2;
	case 0x04:
	    return INC1;
	case 0x05:
	    return INC3;
	case 0xA3:
	    return INC5;
	case 0x20:
	    return JB;
	case 0x10:
	    return JBC;
	case 0x40:
	    return JC;
	case 0x73:
	    return JMP;
	case 0x30:
	    return JNB;
	case 0x50:
	    return JNC;
	case 0x70:
	    return JNZ;
	case 0x60:
	    return JZ;
	case 0x12:
	    return LCALL;
	case 0x02:
	    return LJMP;
	case 0xE5:
	    return MOV2;
	case 0x74:
	    return MOV4;
	case 0xF5:
	    return MOV8;
	case 0x85:
	    return MOV10;
	case 0x75:
	    return MOV12;
	case 0xA2:
	    return MOV16;
	case 0x92:
	    return MOV17;
	case 0x90:
	    return MOV18;
	case 0x93:
	    return MOVC1;
	case 0x83:
	    return MOVC2;
	case 0xE0:
	    return MOVX2;
	case 0xF0:
	    return MOVX4;
	case 0xA4:
	    return MUL;
	case 0x45:
	    return ORL2;
	case 0x44:
	    return ORL4;
	case 0x42:
	    return ORL5;
	case 0x43:
	    return ORL6;
	case 0x72:
	    return ORL7;
	case 0xA0:
	    return ORL8;
	case 0xD0:
	    return POP;
	case 0xC0:
	    return PUSH;
	case 0x22:
	    return RET;
	
	case 0x23:
	    return RL;
	case 0x33:
	    return RLC;
	case 0x03:
	    return RR;
	case 0x13:
	    return RRC;
	case 0xD3:
	    return SETB1;
	case 0xD2:
	    return SETB2;
	case 0x80:
	    return SJMP;
	case 0x95:
	    return SUBB2;
	case 0x94:
	    return SUBB4;
	case 0xC4:
	    return SWAP;
	case 0xC5:
	    return XCH2;
	case 0x65:
	    return XRL2;
	case 0x64:
	    return XRL4;
	case 0x62:
	    return XRL5;
	case 0x63:
	    return XRL6;
	default:
	    break;
    }
    
    // BBBBBBBX
    switch( IR & 0xFE ) {
	case 0x26:
	    return ADD3;
	case 0x36:
	    return ADDC3;
	case 0x56:
	    return ANL3;
	case 0xB6:
	    return CJNE4;
	case 0x16:
	    return DEC4;
	case 0x06:
	    return INC4;
	case 0xE6:
	    return MOV3;
	case 0x86:
	    return MOV11;
	case 0xF6:
	    return MOV13;
	case 0xA6:
	    return MOV14;
	case 0x76:
	    return MOV15;
	case 0xE2:
	    return MOVX1;
	case 0xF2:
	    return MOVX3;
	case 0x46:
	    return ORL3;
	case 0x96:
	    return SUBB3;
	case 0xC6:
	    return XCH3;
	case 0xD6:
	    return XCHD;
	case 0x66:
	    return XRL3;
	    
	default:
	    break;
    }
    
    // BBBBBXXX
    switch( IR & 0xF8 ) {
	case 0x28:
	    return ADD1;
	case 0x38:
	    return ADDC1;
	case 0x58:
	    return ANL1;
	case 0xB8:
	    return CJNE3;
	case 0x18:
	    return DEC2;
	case 0xD8:
	    return DJNZ1;
	case 0x08:
	    return INC2;
	case 0xE8:
	    return MOV1;
	case 0xF8:
	    return MOV5;
	case 0xA8:
	    return MOV6;
	case 0x78:
	    return MOV7;
	case 0x88:
	    return MOV9;
	case 0x48:
	    return ORL1;
	case 0x98:
	    return SUBB1;
	case 0x68:
	    return XRL1;
	case 0xC8:
	    return XCH1;
	    
	default:
	    break;
    }

    // XXXBBBBB
    switch( IR & 0x1F ) {
	case 0x11:
	    return ACALL;
	case 0x01:
	    return AJMP;
	default:
	    break;
    }
    
    printf("Untrasnslated opcode  %04X  at %04X!\n", IR, PC);
    return 0;
}

void TranslateCode(uint8_t *ROM, uint32_t PC, uint32_t size)
{
	uint32_t PC_END = PC + size;
	uint8_t IR;
	
	printf("Translating %04X-%04X\n", PC, PC_END-1);
	
	memset(code+PC, 1, size);
	
	while (PC < PC_END)
	{
		//printf("%02X\n", PC);
		
		IR = ROM[PC];
		uint8_t d = Decode(IR, PC);
		
		if (d == ANL1 || d == ORL1 || d == XRL1 || d == XCH1 || d == DEC2 || d == INC2 || d == MOV1 || d == MOV5 || d == ADD1 || d == ADDC1 ||
		    d == SUBB1)
		{
			ROM[PC++] = d | (IR&7);
		}
		else if (d == ANL2)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ ANL2_X;
			PC++;
		}
		else if (d == ANL3 || d == ORL3 || d == XRL3 || d == XCH3 || d == XCHD || d == DEC4 || d == INC4 || d == MOV3 || d == MOV13
			|| d == MOVX1 || d == MOVX3 || d == ADD3 || d == ADDC3 || d == SUBB3)
		{
			ROM[PC++] = d | (IR&1);
		}
		else if (d == ANL4)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ ANL4_X;
			PC++;
		}
		else if (d == ANL5)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ ANL5_X;
			PC++;
		}
		else if (d == ANL6)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ ANL6_X1;
			ROM[PC+1] = ROM[PC+1] ^ ANL6_X2;
			PC += 2;
		}
		else if (d == ANL7)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ ANL7_X;
			PC++;
		}
		else if (d == ANL8)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ ANL8_X ;
			PC++;
		}
		else if (d == ORL2)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ ORL2_X;
			PC++;
		}
		else if (d == ORL4)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ ORL4_X;
			PC++;
		}
		else if (d == ORL5)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ ORL5_X;
			PC++;
		}
		else if (d == ORL6)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ ORL6_X1;
			ROM[PC+1] = ROM[PC+1] ^ORL6_X2;
			PC += 2;
		}
		else if (d == ORL7)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ ORL7_X;
			PC++;
		}
		else if (d == ORL8)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ ORL8_X;
			PC++;
		}
		else if (d == XRL2)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ XRL2_X;
			PC++;
		}
		else if (d == XRL4)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ XRL4_X;
			PC++;
		}
		else if (d == XRL5)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ XRL5_X;
			PC++;
		}
		else if (d == XRL6)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ XRL6_X1;
			ROM[PC+1] = ROM[PC+1] ^ XRL6_X2;
			PC += 2;
		}
		else if (d == CLR1 || d == CLR2 || d == SETB1 || d == CPL1 || d == CPL2 || d == RL || d == RLC || d == RR || d == RRC || d == SWAP
			|| d == DA || d == DEC1 || d == DIV || d == INC1 || d == INC5 || d == MUL || d == JMP || d == MOVX2 || d == MOVX4 || d == RET)
		{
			ROM[PC++] = d;
		}
		else if (d == CLR3)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ CLR3_X;
			PC++;
		}
		else if (d == SETB2)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ SETB2_X;
			PC++;
		}
		else if (d == CPL3)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ CPL3_X;
			PC++;
		}
		else if (d == XCH2)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ XCH2_X;
			PC++;
		}
		else if (d == LCALL)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ LCALL_X1;
			ROM[PC+1] = ROM[PC+1] ^ LCALL_X2;
			PC += 2;
		}
		else if (d == ACALL)
		{
			ROM[PC++] = d | (IR&0xE0);
			ROM[PC] = ROM[PC] ^ ACALL_X;
			PC++;
		}
		else if (d == CJNE1)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ CJNE1_X1;
			ROM[PC+1] = ROM[PC+1] ^ CJNE1_X2;
			PC += 2;
		}
		else if (d == CJNE2)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ CJNE2_X1;
			ROM[PC+1] = ROM[PC+1] ^ CJNE2_X2;
			PC += 2;
		}
		else if (d == CJNE3)
		{
			ROM[PC++] = d | (IR&7);
			ROM[PC] = ROM[PC] ^ CJNE3_X1;
			ROM[PC+1] = ROM[PC+1] ^ CJNE3_X2;
			PC += 2;
		}
		else if (d == CJNE4)
		{
			ROM[PC++] = d | (IR&1);
			ROM[PC] = ROM[PC] ^ CJNE4_X1;
			ROM[PC+1] = ROM[PC+1] ^ CJNE4_X2;
			PC += 2;
		}
		else if (d == DEC3)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ DEC3_X;
			PC++;
		}
		else if (d == INC3)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ INC3_X;
			PC++;
		}
		else if (d == DJNZ1)
		{
			ROM[PC++] = d | (IR&7);
			ROM[PC] = ROM[PC] ^ DJNZ1_X;
			PC++;
		}
		else if (d == DJNZ2)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ DJNZ2_X1;
			ROM[PC+1] = ROM[PC+1] ^ DJNZ2_X2;
			PC += 2;
		}
		else if (d == POP)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ POP_X;
			PC++;
		}
		else if (d == PUSH)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC]  ^ PUSH_X;
			PC++;
		}
		else if (d == JB)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ JB_X1;
			ROM[PC+1] = ROM[PC+1] ^ JB_X2;
			PC += 2;
		}
		else if (d == JBC)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ JBC_X1;
			ROM[PC+1] = ROM[PC+1] ^ JBC_X2;
			PC += 2;
		}
		else if (d == JC)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ JC_X;
			PC++;
		}
		else if (d == JNB)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ JNB_X1;
			ROM[PC+1] = ROM[PC+1] ^ JNB_X2;
			PC += 2;
		}
		else if (d == JNC)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ JNC_X;
			PC++;
		}
		else if (d == JNZ)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ JNZ_X;
			PC++;
		}
		else if (d == JZ)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ JZ_X;
			PC++;
		}
		else if (d == AJMP)
		{
			ROM[PC++] = d | (IR&0xE0);
			ROM[PC] = ROM[PC] ^ AJMP_X;
			PC++;
		}
		else if (d == LJMP)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ LJMP_X1;
			ROM[PC+1] = ROM[PC+1] ^ LJMP_X2;
			PC += 2;
		}
		else if (d == SJMP)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ SJMP_X;
			PC++;
		}
		else if (d == MOV2)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ MOV2_X;
			PC++;
		}
		else if (d == MOV4)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ MOV4_X;
			PC++;
		}
		else if (d == MOV6)
		{
			ROM[PC++] = d | (IR&7);
			ROM[PC] = ROM[PC] ^ MOV6_X;
			PC++;
		}
		else if (d == MOV7)
		{
			ROM[PC++] = d | (IR&7);
			ROM[PC] = ROM[PC] ^ MOV7_X;
			PC++;
		}
		else if (d == MOV8)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ MOV8_X;
			PC++;
		}
		else if (d == MOV9)
		{
			ROM[PC++] = d | (IR&7);
			ROM[PC] = ROM[PC] ^ MOV9_X;
			PC++;
		}
		else if (d == MOV10)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ MOV10_X1;
			ROM[PC+1] = ROM[PC+1] ^ MOV10_X2;
			PC += 2;
		}
		else if (d == MOV11)
		{
			ROM[PC++] = d | (IR&1);
			ROM[PC] = ROM[PC] ^ MOV11_X;
			PC++;
		}
		else if (d == MOV12)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ MOV12_X1;
			ROM[PC+1] = ROM[PC+1] ^ MOV12_X2;
			PC += 2;
		}
		else if (d == MOV14)
		{
			ROM[PC++] = d | (IR&1);
			ROM[PC] = ROM[PC] ^ MOV14_X;
			PC++;
		}
		else if (d == MOV15)
		{
			ROM[PC++] = d | (IR&1);
			ROM[PC] = ROM[PC] ^ MOV15_X;
			PC++;
		}
		else if (d == MOV16)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ MOV16_X;
			PC++;
		}
		else if (d == MOV17)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ MOV17_X;
			PC++;
		}
		else if (d == MOV18)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ MOV18_X1;
			ROM[PC+1] = ROM[PC+1] ^ MOV18_X2;
			PC += 2;
		}
		else if (d == MOVC1)
		{
			ROM[PC++] = d;
			//ROM[PC] = ROM[PC];
			//PC++;
		}
		else if (d == MOVC2)
		{
			ROM[PC++] = d;
			//ROM[PC] = ROM[PC];
			//PC++;
		}
		else if (d == ADD2)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ ADD2_X;
			PC++;
		}
		else if (d == ADD4)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ ADD4_X;
			PC++;
		}
		else if (d == ADDC2)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ ADDC2_X;
			PC++;
		}
		else if (d == ADDC4)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ ADDC4_X;
			PC++;
		}
		else if (d == SUBB2)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ SUBB2_X;
			PC++;
		}
		else if (d == SUBB4)
		{
			ROM[PC++] = d;
			ROM[PC] = ROM[PC] ^ SUBB4_X;
			PC++;
		}
	}
}

void Translate(uint8_t *ROM, FILE *map, int check_stage2, uint32_t *st2, uint32_t *st2_size, int check_hash, uint32_t *hash, uint32_t *hash_size)
{
	int stage2_flag = 0, hash_flag = 0;
	char line[1024];
	uint32_t stage2 = 0, stage2_size = 0;
	
	if (check_hash)
	{	
		*hash = 0;
		*hash_size = 0;
	}
		
	memset(code, 0, sizeof(code));
	
	while (fgets(line, sizeof(line), map) > 0)
	{		
		if(strstr(line, "CODE)") && strncmp(line, "CONST", 5) != 0)
		{
			char str[32];
			uint32_t addr, size;
			
			sscanf(line, "%s %04X %04X", str, &addr, &size);
			printf("Addr = %X, size = %x\n", addr, size);
			TranslateCode(ROM, addr, size);
		}
		else if (check_stage2 && strstr(line, "_stage2"))
		{
			unsigned int unused;
			
			sscanf(line, "%02X:%04X", &unused, &stage2);
			stage2_flag = 1;
		}
		else if (stage2_flag)
		{
			unsigned int unused;
			
			stage2_flag = 0;
			sscanf(line, "%02X:%04X", &unused, &stage2_size);
			stage2_size -= stage2;
		}
		
		if (check_hash && strstr(line, "_stage1_5_hash") && !strstr(line, "_stage1_5_hash_key"))
		{
			unsigned int unused;
			
			sscanf(line, "%02X:%04X", &unused, hash);
			hash_flag = 1;
		}
		else if (hash_flag)
		{
			unsigned int unused;
			
			hash_flag = 0;
			sscanf(line, "%02X:%04X", &unused, hash_size);
			*hash_size -= *hash;
		}
	}
	
	fclose(map);
	
	// FIX
	for (int i = 0; i < 0x100; i++)
	{
		if (!code[i])
		{
			int len = 0;
			int j = i;
			
			while (!code[j++])
			{
				len++;
			}
			
			TranslateCode(ROM, i, len);
		}
	}
	
	/*TranslateCode(0x0B, 3); 
	TranslateCode(0x0E, 4);
	TranslateCode(0x61, 12);*/
	if (check_stage2 && (stage2 == 0 || stage2_size == 0))
	{
		printf("Warning: stage2 not found.\n");		
	}
	
	if (check_stage2)
	{
		printf("Stage 2: %04X  %d\n", stage2, stage2_size);
		*st2 = stage2;
		*st2_size = stage2_size;
	}
	
	if (check_hash)
	{
		printf("Hash: %04X  %d\n", *hash, *hash_size);		
	}
}

int main(int argc, char *argv[])
{
	FILE *bin, *map, *h, *opc, *k;
	int romsize1, romsize2;	
	uint32_t stage2 = 0, stage2_size = 0;
	uint32_t hash = 0, hash_size = 0;
	
	srand (time(NULL));
	
	if (argc != 9)
	{
		printf("Usage: %s bin1 bin2 map1 map2 keys1 keys2 h_out opcodes_out\n", argv[0]);
		return -1;
	}
	
	h = fopen(argv[7], "w");
	if (!h)
	{
		printf("Cannot open %s\n", argv[7]);
		return -1;
	}
	
	opc = fopen(argv[8], "w");
	if (!opc)
	{
		printf("Cannot open %s\n", argv[8]);
		return -1;
	}
	
	AssignOpcodes(opc);
	fclose(opc);	
	
	bin = fopen(argv[1], "rb");
	if (!bin)
	{
		printf("Cannot open %s\n", argv[1]);
		return -1;
	}
	
	uint8_t *ROM1 = malloc(65536);
	romsize1 = fread(ROM1, 1, 65536, bin);
	fclose(bin);
	
	map = fopen(argv[3], "r");
	if (!map)
	{
		printf("Cannot open %s\n", argv[3]);
		return -1;
	}	
	
		
	Translate(ROM1, map, 0, NULL, NULL, 0, NULL, NULL);
	
	bin = fopen(argv[2], "rb");
	if (!bin)
	{
		printf("Cannot open %s\n", argv[2]);
		return -1;
	}
	
	uint8_t *ROM2 = malloc(65536);
	romsize2 = fread(ROM2, 1, 65536, bin);
	fclose(bin);
	
	map = fopen(argv[4], "r");
	if (!map)
	{
		printf("Cannot open %s\n", argv[4]);
		return -1;
	}
	
	Translate(ROM2, map, 1, &stage2, &stage2_size, 1, &hash, &hash_size);
	
	k = fopen(argv[5], "rb");
	if (!k)
	{
		printf("Cannot open %s\n", argv[5]);
		return -1;
	}
	
	uint8_t rom_key[1024];
	
	int rom_keys_len = fread(rom_key, 1, sizeof(rom_key), k);
	fclose(k);
	
	for (int i = 0; i < romsize1; i++)
	{
		ROM1[i] ^= rom_key[i % rom_keys_len];		
	}
	
	
	k = fopen(argv[6], "rb");
	if (!k)
	{
		printf("Cannot open %s\n", argv[6]);
		return -1;
	}
	if ( fread(rom_key, 1, sizeof(rom_key), k) != rom_keys_len)
	{
		printf("Keys length don't match.\n");
		exit(-1);
	}
	fclose(k);
	
	printf("keys len = %d\n", rom_keys_len);
	
	for (int i = 0; i < romsize2; i++)
	{
		int doit = 1;
		
		if (i >= stage2 && i < (stage2+stage2_size))
		{
			doit = 0;
		}
		else if (i >= hash && i < (hash+hash_size))
		{
			doit = 0;
		}
		
		if (doit)
		{
			ROM2[i] ^= rom_key[i % rom_keys_len];
		}
	}
	
	int gap = ((romsize1+0xF)&~0xF)-romsize1;
	
	printf("Binary 2 at 0x%x\n", romsize1+gap);
	
	int romsize = romsize1+gap+romsize2;
	uint8_t *ROM = malloc(romsize);
	
	memcpy(ROM, ROM1, romsize1);
	
	for (int i = 0; i < gap; i++)
	{
		ROM[romsize1+i] = rand();
	}
	
	memcpy(ROM+romsize1+gap, ROM2, romsize2);
		
	fprintf(h, "static char ROM[%d] =\n{\n\t", romsize);
	
	for (int i = 0; i < romsize; i++)
	{
		fprintf(h, "0x%02X, ", ROM[i]);
		if ((i&7) == 7)
		{
			fprintf(h, "\n\t");
		}
	}
	
	fprintf(h, "\n};\n");
	
	bin = fopen("rom.bin", "wb");
	if (bin)
	{
		fwrite(ROM, 1, romsize, bin);
		fclose(bin);
	}
	
	/*fprintf(h, "static char CODE[%d] =\n{\n\t", romsize);
	
	for (int i = 0; i < romsize; i++)
	{
		fprintf(h, "%d, ", code[i]);
		if ((i&7) == 7)
		{
			fprintf(h, "\n\t");
		}
	}
	
	fprintf(h, "\n};\n");*/
	
	return 0;
}
