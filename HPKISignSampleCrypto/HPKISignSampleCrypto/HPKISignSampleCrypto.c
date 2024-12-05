/*---------------------------------------------------------------------*/
/* FILE NAME  :  HPKISignSampleCrypto.c                 */
/* VERSION    :  1.0                           */
/* DATE      :  2020/10/29                       */
/*---------------------------------------------------------------------*/


/*=====================================================================*/
/*                             INCLUDE                                 */
/*=====================================================================*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>
#include <Windows.h>
#include <wincrypt.h>

/*=====================================================================*/
/*                             DEFINITION                              */
/*=====================================================================*/

#define APROVNAME TEXT("HPKI Crypto Service Provider for Authentication")
#define SPROVNAME TEXT("HPKI Crypto Service Provider for Non Repudiation")
#define HASHSIZE_SHA1 (160 / 8)

/*=====================================================================*/
/*              DEFINITIOIN OF PRIVATE FUNCTION               */
/*=====================================================================*/

/* �v���O�����̎��s�`���@*/
void PrintUsage() {
  printf("Usage : HPKISignSample <prov_type> <method> <pin>\n");
  printf("prov_type:�@auth | sign\n");
  printf("method:�@getcert | sign\n");
  printf("pin:�@HPKICard PIN\n");
}

/* �G���[�������̏��� */
void printErrorAndExit(const char *f)
{
  DWORD errorcode;
  char errmsg[256];

  errorcode = GetLastError();
  FormatMessageA(
    FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS |
    FORMAT_MESSAGE_MAX_WIDTH_MASK,
    NULL,
    errorcode,
    MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT),
    errmsg, sizeof(errmsg) / sizeof(TCHAR),
    NULL);
  printf("%s: 0x%08x (%s).\n", f, errorcode, errmsg);

  exit(EXIT_FAILURE);
}

/* �e�f�[�^(�ؖ����f�[�^�A�����f�[�^)��16�i���\���ŕW���o�� */
void printHex(const BYTE* data, DWORD len, BOOL limit)
{
  DWORD displen;

  if (limit && len > 256)
    displen = 256;
  else
    displen = len;
  for (DWORD i = 0; i < displen; i++) {
    printf("%02x", *(data + i));
    if (i % 16 == 15 || i == displen - 1)
      printf("\n");
    else
      printf(" ");
  }
  if (displen < len)
    printf("...\n");
}

/*
 * getCert: ���p�ҏؖ����擾����
 * �ȉ��̎菇�ŏؖ������擾����B
 * 1. �v���o�C�_�n���h���擾
 * 2. RSA���y�A�̃n���h���擾
 * 3. �ؖ����f�[�^�擾
 * 4. ���n���h���j��
 * 5. �v���o�C�_�n���h�����
 */

void getCert(LPCTSTR pProvName)
{
  HCRYPTPROV hProv;
  HCRYPTKEY  hKey;
  BYTE* certData;
  DWORD certLen;

  /* (1) �Í��v���o�C�_�ƃR���e�i���w�肵�āA�v���o�C�_�n���h�����擾����B */
  if (!CryptAcquireContext(&hProv, NULL, pProvName, PROV_RSA_FULL, 0)) {
    printErrorAndExit("CryptAcquireContext");
  }

  /* (2) �R���e�i�̕ێ�����RSA���y�A�̃n���h�����擾����B */
  if (!CryptGetUserKey(hProv, AT_SIGNATURE, &hKey)) {
    printErrorAndExit("CryptGetUserKey");
  }

  /* (3) ���n���h���ɕt�����闘�p�ҏؖ����f�[�^�̃f�[�^�����擾����B */
  certLen = 0;
  if (!CryptGetKeyParam(hKey, KP_CERTIFICATE, NULL, &certLen, 0)) {
    printErrorAndExit("CryptGetKeyParam(1)");
  }

  certData = malloc(certLen);
  if (certData == NULL) {
    printf("Not enough memory.\n");
    exit(EXIT_FAILURE);
  }

  /* (4) ���n���h���ɕt�����闘�p�ҏؖ����f�[�^�̃f�[�^���擾����B */
  if (!CryptGetKeyParam(hKey, KP_CERTIFICATE, certData, &certLen, 0)) {
    printErrorAndExit("CryptGetKeyParam(2)");
  }

  printf("Certificate:\n");
  printHex(certData, certLen, FALSE);

  free(certData);

  /* (5) ���n���h����j������B */
  if (!CryptDestroyKey(hKey)) {
    printErrorAndExit("CryptDestroyKey");
  }

  /* (6) �v���o�C�_�n���h�����������B */
  if (!CryptReleaseContext(hProv, 0)) {
    printErrorAndExit("CryptReleaseContext");
  }
}

/*
 * sign: ��������
 * �ȉ��̎菇�ŏ��������{����B
 *  1. �v���o�C�_�n���h���擾
 *  2. RSA���y�A�̃n���h���擾
 *  3. �ؖ����f�[�^�擾
 *  4. �n�b�V���I�u�W�F�N�g����
 *  5. �n�b�V���l�ݒ�
 *  6. �����f�[�^���擾
 *  7. PIN�ݒ�
 *  8. �����f�[�^�擾
 *  9. �n�b�V���I�u�W�F�N�g�j��
 * 10. ���n���h���j��
 * 11. �v���o�C�_�n���h�����
 */

void sign(LPCTSTR pProvName, const BYTE *pPinData, DWORD pinLen)
{
  HCRYPTPROV hProv;
  HCRYPTKEY  hKey;
  HCRYPTHASH hHash;
  BYTE* certData;
  DWORD certLen;
  BYTE hashData[256];
  BYTE* sigData;
  DWORD sigLen;

  /* (7) �Í��v���o�C�_�ƃR���e�i���w�肵�āA�v���o�C�_�n���h�����擾����B */
  if (!CryptAcquireContext(&hProv, NULL, pProvName, PROV_RSA_FULL, 0)) {
    printErrorAndExit("CryptAcquireContext");
  }

  /* (8) �R���e�i�̕ێ�����RSA���y�A�̃n���h�����擾����B */
  if (!CryptGetUserKey(hProv, AT_SIGNATURE, &hKey)) {
    printErrorAndExit("CryptGetUserKey");
  }

  /* (9) ���n���h���ɕt�����闘�p�ҏؖ����f�[�^�̃f�[�^�����擾����B */
  certLen = 0;
  if (!CryptGetKeyParam(hKey, KP_CERTIFICATE, NULL, &certLen, 0)) {
    printErrorAndExit("CryptGetKeyParam(1)");
  }

  certData = malloc(certLen);
  if (certData == NULL) {
    printf("Not enough memory.\n");
    exit(EXIT_FAILURE);
  }

  /* (10) ���n���h���ɕt�����闘�p�ҏؖ����f�[�^�̃f�[�^���擾����B */
  if (!CryptGetKeyParam(hKey, KP_CERTIFICATE, certData, &certLen, 0)) {
    printErrorAndExit("CryptGetKeyParam(2)");
  }

  printf("Certificate:\n");
  printHex(certData, certLen, TRUE);

  free(certData);

  /* (11) �n�b�V���I�u�W�F�N�g�̐��� */
  if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) {
    printErrorAndExit("CryptCreateHash");
  }

  /* (12) �����Ώۃf�[�^�̃n�b�V���l�𐶐� (�{�T���v���ł̓_�~�[�f�[�^�g�p) */
  memset(hashData, 0xa5, HASHSIZE_SHA1);

  /* (13) �n�b�V���I�u�W�F�N�g�̃p�����[�^��ݒ� */
  if (!CryptSetHashParam(hHash, HP_HASHVAL, hashData, 0)) {
    printErrorAndExit("CryptSetHashParam");
  }

  /* (14) �n�b�V���l�ɏ������s�������ʂ̃f�[�^�����擾����B */
  sigLen = 0;
  if (!CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, NULL, &sigLen)) {
    printErrorAndExit("CryptSignHash(1)");
  }

  /* (15) �����p����PIN��ݒ肷��B */
  if (!CryptSetProvParam(hProv, PP_SIGNATURE_PIN, pPinData, pinLen)) {
    printErrorAndExit("CryptSetProvParam");
  }

  sigData = malloc(sigLen);
  if (sigData == NULL) {
    printf("Not enough memory.\n");
    exit(EXIT_FAILURE);
  }

  /* (16) �n�b�V���l�ɏ������s�������ʂ��擾����B */
  if (!CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, sigData, &sigLen)) {
    printErrorAndExit("CryptSignHash(2)");
  }

  printf("Signature:\n");
  printHex(sigData, sigLen, FALSE);

  free(sigData);

  /* (17) �n�b�V���I�u�W�F�N�g�j�� */
  if (!CryptDestroyHash(hHash)) {
    printErrorAndExit("CryptDestroyHash");
  }

  /* (18) ���n���h����j������B */
  if (!CryptDestroyKey(hKey)) {
    printErrorAndExit("CryptDestroyKey");
  }

  /* (19) �v���o�C�_�n���h�����������B */
  if (!CryptReleaseContext(hProv, 0)) {
    printErrorAndExit("CryptReleaseContext");
  }
}


/*=====================================================================*/
/*                    Start of main()                             */
/*=====================================================================*/

int main(int argc, char *argv[])
{
  LPCTSTR pProvName;
  BYTE* pPin;
  DWORD pinLen;

  /*--------------------*/
  /* (A) �����̃`�F�b�N */
  /*--------------------*/

  if (argc != 4)
  {
    printf("���s�`��������������܂���B\n");
    PrintUsage();
    exit(EXIT_SUCCESS);
  }

  /* CSP�m�F
   * auth : �d�q�F�ؗpCSP
   * sign : �d�q�����pCSP
  */
  switch (*argv[1]) {
  case 'a':
  case 'A':
    pProvName = APROVNAME;
    break;
  case 's':
  case 'S':
    pProvName = SPROVNAME;
    break;
  default:
    printf("���s�p�����[�^<prov_type>������������܂���B\n");
    PrintUsage();
    exit(EXIT_FAILURE);
    break;
  }

  /* PIN */
  pPin = argv[3];
  pinLen = strlen(argv[3]);

  /*--------------------*/
  /* (B) �����̎��s    */
  /*--------------------*/

  switch (*argv[2]) {
    /* �ؖ����擾 */
  case 'g':
  case 'G':
    printf("�ؖ����擾���� �J�n\n");
    getCert(pProvName);
    printf("\n�ؖ����擾���� ����\n");
    break;
    /* ���� */
  case 's':
  case 'S':
    printf("�������� �J�n\n");
    sign(pProvName, pPin, pinLen);
    printf("\n�������� ����\n");
    break;
  default:
    printf("���s�p�����[�^<method>������������܂���B\n");
    PrintUsage();
    exit(EXIT_FAILURE);
    break;
  }

  exit(EXIT_SUCCESS);
}
/*=====================================================================*/
/*             End of main()                   */
/*=====================================================================*/