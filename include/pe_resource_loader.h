#ifndef PE_RESOURCE_LOADER_HPP
#define PE_RESOURCE_LOADER_HPP

#include <stdint.h>
#include <stdio.h>

typedef struct {
  FILE *  fd;
  uint32_t resource_virtual_address;
  uint32_t resource_offset;
} PeResourceLoader;

PeResourceLoader * PeResourceLoader_Open(const char * file_path);
PeResourceLoader * PeResourceLoader_Close(PeResourceLoader * loader);
uint32_t * PeResourceLoader_GetLanguageIds(PeResourceLoader * loader, uint16_t * language_count);
uint16_t PeResourceLoader_GetStringCount(PeResourceLoader *loader);
uint8_t * PeResourceLoader_GetString(PeResourceLoader * loader, uint16_t language_id, uint32_t string_id, uint16_t * length);

// Possible languages
typedef enum {
  PRL_LANG_AF=0x0036,
  PRL_LANG_AF_ZA=0x0436,
  PRL_LANG_AM=0x005E,
  PRL_LANG_AM_ET=0x045E,
  PRL_LANG_AR=0x0001,
  PRL_LANG_AR_AE=0x3801,
  PRL_LANG_AR_BH=0x3C01,
  PRL_LANG_AR_DZ=0x1401,
  PRL_LANG_AR_EG=0x0c01,
  PRL_LANG_AR_IQ=0x0801,
  PRL_LANG_AR_JO=0x2C01,
  PRL_LANG_AR_KW=0x3401,
  PRL_LANG_AR_LB=0x3001,
  PRL_LANG_AR_LY=0x1001,
  PRL_LANG_AR_MA=0x1801,
  PRL_LANG_ARN=0x007A,
  PRL_LANG_ARN_CL=0x047A,
  PRL_LANG_AR_OM=0x2001,
  PRL_LANG_AR_QA=0x4001,
  PRL_LANG_AR_SA=0x0401,
  PRL_LANG_AR_SY=0x2801,
  PRL_LANG_AR_TN=0x1C01,
  PRL_LANG_AR_YE=0x2401,
  PRL_LANG_AS=0x004D,
  PRL_LANG_AS_IN=0x044D,
  PRL_LANG_AZ=0x002C,
  PRL_LANG_AZ_CYRL=0x742C,
  PRL_LANG_AZ_CYRL_AZ=0x082C,
  PRL_LANG_AZ_LATN=0x782C,
  PRL_LANG_AZ_LATN_AZ=0x042C,
  PRL_LANG_BA=0x006D,
  PRL_LANG_BA_RU=0x046D,
  PRL_LANG_BE=0x0023,
  PRL_LANG_BE_BY=0x0423,
  PRL_LANG_BG=0x0002,
  PRL_LANG_BG_BG=0x0402,
  PRL_LANG_BN=0x0045,
  PRL_LANG_BN_BD=0x0845,
  PRL_LANG_BN_IN=0x0445,
  PRL_LANG_BO=0x0051,
  PRL_LANG_BO_CN=0x0451,
  PRL_LANG_BR=0x007E,
  PRL_LANG_BR_FR=0x047E,
  PRL_LANG_BS=0x781A,
  PRL_LANG_BS_CYRL=0x641A,
  PRL_LANG_BS_CYRL_BA=0x201A,
  PRL_LANG_BS_LATN=0x681A,
  PRL_LANG_BS_LATN_BA=0x141A,
  PRL_LANG_CA=0x0003,
  PRL_LANG_CA_ES=0x0403,
  PRL_LANG_CA_ES_VALENCIA=0x0803,
  PRL_LANG_CHR=0x005C,
  PRL_LANG_CHR_CHER=0x7c5C,
  PRL_LANG_CHR_CHER_US=0x045C,
  PRL_LANG_CO=0x0083,
  PRL_LANG_CO_FR=0x0483,
  PRL_LANG_CS=0x0005,
  PRL_LANG_CS_CZ=0x0405,
  PRL_LANG_CY=0x0052,
  PRL_LANG_CY_GB=0x0452,
  PRL_LANG_DA=0x0006,
  PRL_LANG_DA_DK=0x0406,
  PRL_LANG_DE=0x0007,
  PRL_LANG_DE_AT=0x0C07,
  PRL_LANG_DE_CH=0x0807,
  PRL_LANG_DE_DE=0x0407,
  PRL_LANG_DE_LI=0x1407,
  PRL_LANG_DE_LU=0x1007,
  PRL_LANG_DSB=0x7C2E,
  PRL_LANG_DSB_DE=0x082E,
  PRL_LANG_DV=0x0065,
  PRL_LANG_DV_MV=0x0465,
  PRL_LANG_EL=0x0008,
  PRL_LANG_EL_GR=0x0408,
  PRL_LANG_EN_029=0x2409,
  PRL_LANG_EN=0x0009,
  PRL_LANG_EN_AE=0x4C09,
  PRL_LANG_EN_AU=0x0C09,
  PRL_LANG_EN_BZ=0x2809,
  PRL_LANG_EN_CA=0x1009,
  PRL_LANG_EN_GB=0x0809,
  PRL_LANG_EN_HK=0x3C09,
  PRL_LANG_EN_IE=0x1809,
  PRL_LANG_EN_IN=0x4009,
  PRL_LANG_EN_MY=0x4409,
  PRL_LANG_EN_NZ=0x1409,
  PRL_LANG_EN_PH=0x3409,
  PRL_LANG_EN_SG=0x4809,
  PRL_LANG_EN_TT=0x2c09,
  PRL_LANG_EN_US=0x0409,
  PRL_LANG_EN_ZA=0x1C09,
  PRL_LANG_EN_ZW=0x3009,
  PRL_LANG_ES=0x000A,
  PRL_LANG_ES_419=0x580A,
  PRL_LANG_ES_AR=0x2C0A,
  PRL_LANG_ES_BO=0x400A,
  PRL_LANG_ES_CL=0x340A,
  PRL_LANG_ES_CO=0x240A,
  PRL_LANG_ES_CR=0x140A,
  PRL_LANG_ES_CU=0x5c0A,
  PRL_LANG_ES_DO=0x1c0A,
  PRL_LANG_ES_EC=0x300A,
  PRL_LANG_ES_ES=0x0c0A,
  PRL_LANG_ES_ES_TRADNL=0x040A,
  PRL_LANG_ES_GT=0x100A,
  PRL_LANG_ES_HN=0x480A,
  PRL_LANG_ES_MX=0x080A,
  PRL_LANG_ES_NI=0x4C0A,
  PRL_LANG_ES_PA=0x180A,
  PRL_LANG_ES_PE=0x280A,
  PRL_LANG_ES_PR=0x500A,
  PRL_LANG_ES_PY=0x3C0A,
  PRL_LANG_ES_SV=0x440A,
  PRL_LANG_ES_US=0x540A,
  PRL_LANG_ES_UY=0x380A,
  PRL_LANG_ES_VE=0x200A,
  PRL_LANG_ET=0x0025,
  PRL_LANG_ET_EE=0x0425,
  PRL_LANG_EU=0x002D,
  PRL_LANG_EU_ES=0x042D,
  PRL_LANG_FA=0x0029,
  PRL_LANG_FA_IR=0x0429,
  PRL_LANG_FF=0x0067,
  PRL_LANG_FF_LATN=0x7C67,
  PRL_LANG_FF_LATN_NG=0x0467,
  PRL_LANG_FF_LATN_SN=0x0867,
  PRL_LANG_FI=0x000B,
  PRL_LANG_FI_FI=0x040B,
  PRL_LANG_FIL=0x0064,
  PRL_LANG_FIL_PH=0x0464,
  PRL_LANG_FO=0x0038,
  PRL_LANG_FO_FO=0x0438,
  PRL_LANG_FR_029=0x1C0C,
  PRL_LANG_FR=0x000C,
  PRL_LANG_FR_BE=0x080C,
  PRL_LANG_FR_CA=0x0c0C,
  PRL_LANG_FR_CD=0x240C,
  PRL_LANG_FR_CH=0x100C,
  PRL_LANG_FR_CI=0x300C,
  PRL_LANG_FR_CM=0x2c0C,
  PRL_LANG_FR_FR=0x040C,
  PRL_LANG_FR_HT=0x3c0C,
  PRL_LANG_FR_LU=0x140C,
  PRL_LANG_FR_MA=0x380C,
  PRL_LANG_FR_MC=0x180C,
  PRL_LANG_FR_ML=0x340C,
  PRL_LANG_FR_RE=0x200C,
  PRL_LANG_FR_SN=0x280C,
  PRL_LANG_FY=0x0062,
  PRL_LANG_FY_NL=0x0462,
  PRL_LANG_GA=0x003C,
  PRL_LANG_GA_IE=0x083C,
  PRL_LANG_GD=0x0091,
  PRL_LANG_GD_GB=0x0491,
  PRL_LANG_GL=0x0056,
  PRL_LANG_GL_ES=0x0456,
  PRL_LANG_GN=0x0074,
  PRL_LANG_GN_PY=0x0474,
  PRL_LANG_GSW=0x0084,
  PRL_LANG_GSW_FR=0x0484,
  PRL_LANG_GU=0x0047,
  PRL_LANG_GU_IN=0x0447,
  PRL_LANG_HA=0x0068,
  PRL_LANG_HA_LATN=0x7C68,
  PRL_LANG_HA_LATN_NG=0x0468,
  PRL_LANG_HAW=0x0075,
  PRL_LANG_HAW_US=0x0475,
  PRL_LANG_HE=0x000D,
  PRL_LANG_HE_IL=0x040D,
  PRL_LANG_HI=0x0039,
  PRL_LANG_HI_IN=0x0439,
  PRL_LANG_HR=0x001A,
  PRL_LANG_HR_BA=0x101A,
  PRL_LANG_HR_HR=0x041A,
  PRL_LANG_HSB=0x002E,
  PRL_LANG_HSB_DE=0x042E,
  PRL_LANG_HU=0x000E,
  PRL_LANG_HU_HU=0x040E,
  PRL_LANG_HY=0x002B,
  PRL_LANG_HY_AM=0x042B,
  PRL_LANG_ID=0x0021,
  PRL_LANG_ID_ID=0x0421,
  PRL_LANG_IG=0x0070,
  PRL_LANG_IG_NG=0x0470,
  PRL_LANG_II=0x0078,
  PRL_LANG_II_CN=0x0478,
  PRL_LANG_IS=0x000F,
  PRL_LANG_IS_IS=0x040F,
  PRL_LANG_IT=0x0010,
  PRL_LANG_IT_CH=0x0810,
  PRL_LANG_IT_IT=0x0410,
  PRL_LANG_IU=0x005D,
  PRL_LANG_IU_CANS=0x785D,
  PRL_LANG_IU_CANS_CA=0x045d,
  PRL_LANG_IU_LATN=0x7C5D,
  PRL_LANG_IU_LATN_CA=0x085D,
  PRL_LANG_JA=0x0011,
  PRL_LANG_JA_JP=0x0411,
  PRL_LANG_KA=0x0037,
  PRL_LANG_KA_GE=0x0437,
  PRL_LANG_KK=0x003F,
  PRL_LANG_KK_KZ=0x043F,
  PRL_LANG_KL=0x006F,
  PRL_LANG_KL_GL=0x046F,
  PRL_LANG_KM=0x0053,
  PRL_LANG_KM_KH=0x0453,
  PRL_LANG_KN=0x004B,
  PRL_LANG_KN_IN=0x044B,
  PRL_LANG_KO=0x0012,
  PRL_LANG_KOK=0x0057,
  PRL_LANG_KOK_IN=0x0457,
  PRL_LANG_KO_KR=0x0412,
  PRL_LANG_KR_LATN_NG=0x0471,
  PRL_LANG_KS=0x0060,
  PRL_LANG_KS_ARAB=0x0460,
  PRL_LANG_KS_DEVA_IN=0x0860,
  PRL_LANG_KU=0x0092,
  PRL_LANG_KU_ARAB=0x7c92,
  PRL_LANG_KU_ARAB_IQ=0x0492,
  PRL_LANG_KY=0x0040,
  PRL_LANG_KY_KG=0x0440,
  PRL_LANG_LA_VA=0x0476,
  PRL_LANG_LB=0x006E,
  PRL_LANG_LB_LU=0x046E,
  PRL_LANG_LO=0x0054,
  PRL_LANG_LO_LA=0x0454,
  PRL_LANG_LT=0x0027,
  PRL_LANG_LT_LT=0x0427,
  PRL_LANG_LV=0x0026,
  PRL_LANG_LV_LV=0x0426,
  PRL_LANG_MI=0x0081,
  PRL_LANG_MI_NZ=0x0481,
  PRL_LANG_MK=0x002F,
  PRL_LANG_MK_MK=0x042F,
  PRL_LANG_ML=0x004C,
  PRL_LANG_ML_IN=0x044C,
  PRL_LANG_MN=0x0050,
  PRL_LANG_MN_CYRL=0x7850,
  PRL_LANG_MN_MN=0x0450,
  PRL_LANG_MN_MONG=0x7C50,
  PRL_LANG_MN_MONG_CN=0x0850,
  PRL_LANG_MN_MONG_MN=0x0C50,
  PRL_LANG_MOH=0x007C,
  PRL_LANG_MOH_CA=0x047C,
  PRL_LANG_MR=0x004E,
  PRL_LANG_MR_IN=0x044E,
  PRL_LANG_MS=0x003E,
  PRL_LANG_MS_BN=0x083E,
  PRL_LANG_MS_MY=0x043E,
  PRL_LANG_MT=0x003A,
  PRL_LANG_MT_MT=0x043A,
  PRL_LANG_MY=0x0055,
  PRL_LANG_MY_MM=0x0455,
  PRL_LANG_NB=0x7C14,
  PRL_LANG_NB_NO=0x0414,
  PRL_LANG_NE=0x0061,
  PRL_LANG_NE_IN=0x0861,
  PRL_LANG_NE_NP=0x0461,
  PRL_LANG_NL=0x0013,
  PRL_LANG_NL_BE=0x0813,
  PRL_LANG_NL_NL=0x0413,
  PRL_LANG_NN=0x7814,
  PRL_LANG_NN_NO=0x0814,
  PRL_LANG_NO=0x0014,
  PRL_LANG_NSO=0x006C,
  PRL_LANG_NSO_ZA=0x046C,
  PRL_LANG_OC=0x0082,
  PRL_LANG_OC_FR=0x0482,
  PRL_LANG_OM=0x0072,
  PRL_LANG_OM_ET=0x0472,
  PRL_LANG_OR=0x0048,
  PRL_LANG_OR_IN=0x0448,
  PRL_LANG_PA=0x0046,
  PRL_LANG_PA_ARAB=0x7C46,
  PRL_LANG_PA_ARAB_PK=0x0846,
  PRL_LANG_PA_IN=0x0446,
  PRL_LANG_PL=0x0015,
  PRL_LANG_PL_PL=0x0415,
  PRL_LANG_PRS=0x008C,
  PRL_LANG_PRS_AF=0x048C,
  PRL_LANG_PS=0x0063,
  PRL_LANG_PS_AF=0x0463,
  PRL_LANG_PT=0x0016,
  PRL_LANG_PT_BR=0x0416,
  PRL_LANG_PT_PT=0x0816,
  PRL_LANG_QPS_PLOC=0x0501,
  PRL_LANG_QPS_PLOCA=0x05FE,
  PRL_LANG_QPS_PLOCM=0x09FF,
  PRL_LANG_QUC=0x0086,
  PRL_LANG_QUC_LATN_GT=0x0486,
  PRL_LANG_QUZ=0x006B,
  PRL_LANG_QUZ_BO=0x046B,
  PRL_LANG_QUZ_EC=0x086B,
  PRL_LANG_QUZ_PE=0x0C6B,
  PRL_LANG_RM=0x0017,
  PRL_LANG_RM_CH=0x0417,
  PRL_LANG_RO=0x0018,
  PRL_LANG_RO_MD=0x0818,
  PRL_LANG_RO_RO=0x0418,
  PRL_LANG_RU=0x0019,
  PRL_LANG_RU_MD=0x0819,
  PRL_LANG_RU_RU=0x0419,
  PRL_LANG_RW=0x0087,
  PRL_LANG_RW_RW=0x0487,
  PRL_LANG_SA=0x004F,
  PRL_LANG_SAH=0x0085,
  PRL_LANG_SAH_RU=0x0485,
  PRL_LANG_SA_IN=0x044F,
  PRL_LANG_SD=0x0059,
  PRL_LANG_SD_ARAB=0x7C59,
  PRL_LANG_SD_ARAB_PK=0x0859,
  PRL_LANG_SE=0x003B,
  PRL_LANG_SE_FI=0x0C3B,
  PRL_LANG_SE_NO=0x043B,
  PRL_LANG_SE_SE=0x083B,
  PRL_LANG_SI=0x005B,
  PRL_LANG_SI_LK=0x045B,
  PRL_LANG_SK=0x001B,
  PRL_LANG_SK_SK=0x041B,
  PRL_LANG_SL=0x0024,
  PRL_LANG_SL_SI=0x0424,
  PRL_LANG_SMA=0x783B,
  PRL_LANG_SMA_NO=0x183B,
  PRL_LANG_SMA_SE=0x1C3B,
  PRL_LANG_SMJ=0x7C3B,
  PRL_LANG_SMJ_NO=0x103B,
  PRL_LANG_SMJ_SE=0x143B,
  PRL_LANG_SMN=0x703B,
  PRL_LANG_SMN_FI=0x243B,
  PRL_LANG_SMS=0x743B,
  PRL_LANG_SMS_FI=0x203B,
  PRL_LANG_SO=0x0077,
  PRL_LANG_SO_SO=0x0477,
  PRL_LANG_SQ=0x001C,
  PRL_LANG_SQ_AL=0x041C,
  PRL_LANG_SR=0x7C1A,
  PRL_LANG_SR_CYRL=0x6C1A,
  PRL_LANG_SR_CYRL_BA=0x1C1A,
  PRL_LANG_SR_CYRL_CS=0x0C1A,
  PRL_LANG_SR_CYRL_ME=0x301A,
  PRL_LANG_SR_CYRL_RS=0x281A,
  PRL_LANG_SR_LATN=0x701A,
  PRL_LANG_SR_LATN_BA=0x181A,
  PRL_LANG_SR_LATN_CS=0x081A,
  PRL_LANG_SR_LATN_ME=0x2c1A,
  PRL_LANG_SR_LATN_RS=0x241A,
  PRL_LANG_ST=0x0030,
  PRL_LANG_ST_ZA=0x0430,
  PRL_LANG_SV=0x001D,
  PRL_LANG_SV_FI=0x081D,
  PRL_LANG_SV_SE=0x041D,
  PRL_LANG_SW=0x0041,
  PRL_LANG_SW_KE=0x0441,
  PRL_LANG_SYR=0x005A,
  PRL_LANG_SYR_SY=0x045A,
  PRL_LANG_TA=0x0049,
  PRL_LANG_TA_IN=0x0449,
  PRL_LANG_TA_LK=0x0849,
  PRL_LANG_TE=0x004A,
  PRL_LANG_TE_IN=0x044A,
  PRL_LANG_TG=0x0028,
  PRL_LANG_TG_CYRL=0x7C28,
  PRL_LANG_TG_CYRL_TJ=0x0428,
  PRL_LANG_TH=0x001E,
  PRL_LANG_TH_TH=0x041E,
  PRL_LANG_TI=0x0073,
  PRL_LANG_TI_ER=0x0873,
  PRL_LANG_TI_ET=0x0473,
  PRL_LANG_TK=0x0042,
  PRL_LANG_TK_TM=0x0442,
  PRL_LANG_TN=0x0032,
  PRL_LANG_TN_BW=0x0832,
  PRL_LANG_TN_ZA=0x0432,
  PRL_LANG_TR=0x001F,
  PRL_LANG_TR_TR=0x041F,
  PRL_LANG_TS=0x0031,
  PRL_LANG_TS_ZA=0x0431,
  PRL_LANG_TT=0x0044,
  PRL_LANG_TT_RU=0x0444,
  PRL_LANG_TZM=0x005F,
  PRL_LANG_TZM_ARAB_MA=0x045F,
  PRL_LANG_TZM_LATN=0x7C5F,
  PRL_LANG_TZM_LATN_DZ=0x085F,
  PRL_LANG_UG=0x0080,
  PRL_LANG_UG_CN=0x0480,
  PRL_LANG_UK=0x0022,
  PRL_LANG_UK_UA=0x0422,
  PRL_LANG_UR=0x0020,
  PRL_LANG_UR_IN=0x0820,
  PRL_LANG_UR_PK=0x0420,
  PRL_LANG_UZ=0x0043,
  PRL_LANG_UZ_CYRL=0x7843,
  PRL_LANG_UZ_CYRL_UZ=0x0843,
  PRL_LANG_UZ_LATN=0x7C43,
  PRL_LANG_UZ_LATN_UZ=0x0443,
  PRL_LANG_VE=0x0033,
  PRL_LANG_VE_ZA=0x0433,
  PRL_LANG_VI=0x002A,
  PRL_LANG_VI_VN=0x042A,
  PRL_LANG_WO=0x0088,
  PRL_LANG_WO_SN=0x0488,
  PRL_LANG_XH=0x0034,
  PRL_LANG_XH_ZA=0x0434,
  PRL_LANG_YI_001=0x043D,
  PRL_LANG_YO=0x006A,
  PRL_LANG_YO_NG=0x046A,
  PRL_LANG_ZH=0x7804,
  PRL_LANG_ZH_CN=0x0804,
  PRL_LANG_ZH_HANS=0x0004,
  PRL_LANG_ZH_HANT=0x7C04,
  PRL_LANG_ZH_HK=0x0C04,
  PRL_LANG_ZH_MO=0x1404,
  PRL_LANG_ZH_SG=0x1004,
  PRL_LANG_ZH_TW=0x0404,
  PRL_LANG_ZU=0x0035,
  PRL_LANG_ZU_ZA=0x0435,
} PRL_Lang;

#endif // PE_RESOURCE_LOADER_HPP