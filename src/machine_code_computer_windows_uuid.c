#include <Windows.h>
#include <wincrypt.h>

#include "cryptolens/machine_code_computer.h"
#include "cryptolens/error.h"

#define CHUNK_SIZE 128
#define INITIAL_BUFFER_SIZE 1024

static
size_t
SHA256(cryptolens_error_t * e, char* data, size_t n, char * machine_code, size_t machine_code_length)
{
  // Initialization from https://devblogs.microsoft.com/oldnewthing/20160127-00/?p=92934
  HCRYPTPROV hProv = 0;
  HCRYPTHASH hHash = 0;

  BYTE* pbHash = NULL;
  DWORD dwHashLen;
  DWORD dwHashLenSize = sizeof(DWORD);

  CHAR HEX[] = "0123456789ABCDEF";

  size_t result = 1;

  if (cryptolens_check_error(e)) { goto cleanup; }


  if (!CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
  {
    cryptolens_set_error(e, CRYPTOLENS_ES_MC, 1, 0);
    goto cleanup;
  }

  if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
  {
    cryptolens_set_error(e, CRYPTOLENS_ES_MC, 2, 0);
    goto cleanup;
  }

  if (n > 0xFFFFFFFF) { cryptolens_set_error(e, CRYPTOLENS_ES_MC, 3, 0); goto cleanup; }

  if (!CryptHashData(hHash, (const BYTE*)data, (DWORD)n, 0))
  {
    cryptolens_set_error(e, CRYPTOLENS_ES_MC, 4, 0);
    goto cleanup;
  }

  if (!CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&dwHashLen, &dwHashLenSize, 0))
  {
    cryptolens_set_error(e, CRYPTOLENS_ES_MC, 5, 0);
    goto cleanup;
  }

  if (!(pbHash = (BYTE*)malloc(dwHashLen)))
  {
    cryptolens_set_error(e, CRYPTOLENS_ES_MC, 6, 0);
    goto cleanup;
  }

  if (!CryptGetHashParam(hHash, HP_HASHVAL, pbHash, &dwHashLen, 0))
  {
    cryptolens_set_error(e, CRYPTOLENS_ES_MC, 7, 0);
    goto cleanup;
  }

  if (machine_code_length < 2*dwHashLen+1) { cryptolens_set_error(e, CRYPTOLENS_ES_MC, 8, 0); goto cleanup; }

  for (size_t i = 0; i < dwHashLen; ++i)
  {
    BYTE x = pbHash[i];
    int x1 = (x & 0xF0) >> 4;
    int x2 = (x & 0xF) >> 0;
    machine_code[2*i]   = HEX[x1];
    machine_code[2*i+1] = HEX[x2];
  }
  machine_code[2*dwHashLen] = '\0';

  result = 0;

cleanup:
  if (hHash) { CryptDestroyHash(hHash); }
  if (hProv) { CryptReleaseContext(hProv, 0); }
  free(pbHash);

  return result;
}

struct buffer {
    int s;
    int p;
    char* b;
};

static
BOOL
cryptolens_buffer_init(struct buffer * b)
{
  b->p = 0;
  b->b = (char *)malloc(INITIAL_BUFFER_SIZE * sizeof(char));
  b->s = b->b == NULL ? 0 : INITIAL_BUFFER_SIZE;

  return b->b != NULL;
}

static
void
cryptolens_buffer_destroy(struct buffer * b)
{
  free(b->b);
  b->s = 0;
  b->p = 0;
  b->b = NULL;
}

static
int
cryptolens_buffer_check_size(struct buffer * b)
{
  char * tmp = NULL;
  int new_size = 0;

  if (b->p + CHUNK_SIZE < b->s) {
    if (b->b == NULL) {
      new_size = INITIAL_BUFFER_SIZE;
      tmp = (char *)malloc(new_size * sizeof(char));
    } else {
      new_size = 2 * b->s;
      tmp = (char *)realloc(b->b, new_size * sizeof(char));
    }

    if (tmp == NULL) { return 0; }

    b->b = tmp;
    b->s = new_size;
  }

  return 1;
}

static
BOOL
create_pipes(
  cryptolens_error_t * e,
  HANDLE * read_pipe,
  HANDLE * write_pipe,
  LPCWSTR pipe_name
)
{
  HANDLE r = INVALID_HANDLE_VALUE;
  HANDLE w = INVALID_HANDLE_VALUE;
  SECURITY_ATTRIBUTES sa;

  if (cryptolens_check_error(e)) { return FALSE; }

  sa.nLength = sizeof(SECURITY_ATTRIBUTES);
  sa.bInheritHandle = TRUE;
  sa.lpSecurityDescriptor = NULL;

  r = CreateNamedPipe(
    pipe_name, 
    PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
    PIPE_TYPE_BYTE | PIPE_WAIT,
    1,
    INITIAL_BUFFER_SIZE,
    INITIAL_BUFFER_SIZE,
    15 * 1000,
    &sa
  );

  if (!r) { cryptolens_set_error(e, CRYPTOLENS_ES_MC, 9, 0); return FALSE; }

  w = CreateFile(
    pipe_name,
    GENERIC_WRITE,
    0,
    &sa,
    OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
    NULL
  );

  if (w == INVALID_HANDLE_VALUE) {
    CloseHandle(r);
    cryptolens_set_error(e, CRYPTOLENS_ES_MC, 10, 0); 
    return FALSE;
  }

  *read_pipe = r;
  *write_pipe = w;

  return TRUE;
}

static
BOOL
create_process(
  cryptolens_error_t * e,
  HANDLE * p_out_read,
  HANDLE * p_err_read,
  HANDLE * child_process,
  HANDLE * child_thread
)
{
  BOOL r = 0;
  HANDLE p_out_write = INVALID_HANDLE_VALUE;
  HANDLE p_err_write = INVALID_HANDLE_VALUE;
  PROCESS_INFORMATION pi;
  STARTUPINFO si;
  wchar_t command[] = L"cmd.exe /c powershell.exe -Command \"(Get-CimInstance -Class Win32_ComputerSystemProduct).UUID\"";

  if (cryptolens_check_error(e)) { return FALSE; }

  *p_out_read = INVALID_HANDLE_VALUE;
  *p_err_read = INVALID_HANDLE_VALUE;

  if (!create_pipes(e, p_out_read, &p_out_write, L"\\\\.\\Pipe\\oiwejfoiwjkoejwf")) { cryptolens_set_error(e, CRYPTOLENS_ES_MC, 11, 0); goto error; }
  if (!create_pipes(e, p_err_read, &p_err_write, L"\\\\.\\Pipe\\oiwijfodgergwergoejwf")) { cryptolens_set_error(e, CRYPTOLENS_ES_MC, 12, 0); goto error; }

  if (!SetHandleInformation(*p_out_read, HANDLE_FLAG_INHERIT, 0)) { cryptolens_set_error(e, CRYPTOLENS_ES_MC, 13, GetLastError()); goto error; }
  if (!SetHandleInformation(*p_err_read, HANDLE_FLAG_INHERIT, 0)) { cryptolens_set_error(e, CRYPTOLENS_ES_MC, 14, GetLastError()); goto error; }

  ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

  ZeroMemory(&si, sizeof(STARTUPINFO));
  si.cb = sizeof(STARTUPINFO);
  si.hStdOutput = p_out_write;
  si.hStdError = p_err_write;
  si.dwFlags |= STARTF_USESTDHANDLES;

  r = CreateProcess(
                NULL,
                command,
                NULL,
                NULL,
                TRUE,
                CREATE_NO_WINDOW,
                NULL,
                NULL,
                &si,
                &pi
  );

  CloseHandle(p_out_write);
  CloseHandle(p_err_write);

  if (!r) { cryptolens_set_error(e, CRYPTOLENS_ES_MC, 15, 0); goto error; }

  goto exit;
error:
  return FALSE;
exit:
  *child_process = pi.hProcess;
  *child_thread = pi.hThread;
  return TRUE;
}

static
void
overlapped_read_complete(
  DWORD dwErrorCode,
  DWORD dwNumberOfBytesTransfered, 
  LPOVERLAPPED lpOverlapped
)
{
  struct buffer * b = (struct buffer *)lpOverlapped->hEvent;

  b->p += dwNumberOfBytesTransfered;
}

char *
cryptolens_MC_get_machine_code(cryptolens_error_t * e)
{
  BOOL r = 0;
  DWORD c = 0;
  struct buffer b_out;
  struct buffer b_err;
  HANDLE p_out_read = INVALID_HANDLE_VALUE;
  HANDLE p_err_read = INVALID_HANDLE_VALUE;
  HANDLE child_process = INVALID_HANDLE_VALUE;
  HANDLE child_thread = INVALID_HANDLE_VALUE;
  char * machine_code = NULL;

  OVERLAPPED o_out;
  OVERLAPPED o_err;
  HANDLE wait_handles[2];
  BOOL reading_out = TRUE;
  BOOL reading_err = TRUE;

  r  = cryptolens_buffer_init(&b_out);
  if (!cryptolens_buffer_init(&b_err)) { cryptolens_set_error(e, CRYPTOLENS_ES_MC, 17, 0); goto error; }
  if (!r) { cryptolens_set_error(e, CRYPTOLENS_ES_MC, 16, 0); goto error; } 

  create_process(e, &p_out_read, &p_err_read, &child_process, &child_thread);
  if (cryptolens_check_error(e)) { goto error; }

  ZeroMemory(&o_out, sizeof(OVERLAPPED));
  ZeroMemory(&o_err, sizeof(OVERLAPPED));

  o_out.hEvent = (LPVOID)&b_out;
  o_err.hEvent = (LPVOID)&b_err;

  r = 0;

  r |= ReadFileEx(p_out_read, b_out.b + b_out.p, CHUNK_SIZE, (LPOVERLAPPED)&o_out, &overlapped_read_complete);
  r |= ReadFileEx(p_err_read, b_err.b + b_err.p, CHUNK_SIZE, (LPOVERLAPPED)&o_err, &overlapped_read_complete);

  if (!r) {
    cryptolens_set_error(e, CRYPTOLENS_ES_MC, 18, GetLastError());
    goto error;
  }

  while (reading_out && reading_err) {
    c = 0;

    if (reading_out) {
      wait_handles[c] = p_out_read;
      c += 1;
    }

    if (reading_err) {
      wait_handles[c] = p_err_read;
      c += 1;
    }

    c = WaitForMultipleObjectsEx(c, wait_handles, FALSE, INFINITE, TRUE);

    /*
     * Check stderr
     */

    r = GetOverlappedResult(p_err_read, &o_err, &c, FALSE);

    if (r) {
      // Success....
      if (c > 0) {
        cryptolens_set_error(e, CRYPTOLENS_ES_MC, 19, 0);
        goto error;
      } else {
        r = ReadFileEx(p_err_read, b_err.b + b_err.p, CHUNK_SIZE, (LPOVERLAPPED)&o_err, &overlapped_read_complete);
        if (!r) {
            cryptolens_set_error(e, CRYPTOLENS_ES_MC, 101, GetLastError());
            goto error;
        }
      }
    } else {
      c = GetLastError();

      switch (c) {
      case ERROR_IO_INCOMPLETE:
        // Did not read, do nothing
      break;

      case ERROR_HANDLE_EOF:
      case ERROR_BROKEN_PIPE:
        // EOF
        reading_err = FALSE;
      break;

      default:
        // Other error
        cryptolens_set_error(e, CRYPTOLENS_ES_MC, 20, c);
        goto error;
      break;
      }
    }

    /*
     * Check stdout
     */

    r = GetOverlappedResult(p_out_read, &o_out, &c, FALSE);

    if (r) {
      c = cryptolens_buffer_check_size(&b_out);
      if (!c) { cryptolens_set_error(e, CRYPTOLENS_ES_MC, 100, 0); goto error; }

      r = ReadFileEx(p_out_read, b_out.b + b_out.p, CHUNK_SIZE, (LPOVERLAPPED)&o_out, &overlapped_read_complete);

      if (!r) {
        c = GetLastError();

        switch (c) {
        case ERROR_HANDLE_EOF:
        case ERROR_BROKEN_PIPE:
          // EOF
          reading_out = FALSE;
        break;

        default:
          // Other error
          cryptolens_set_error(e, CRYPTOLENS_ES_MC, 21, c);
          goto error;
        break;
        }
      }
    } else {
      c = GetLastError();

      switch (c) {
      case ERROR_IO_INCOMPLETE:
        // Did not read, do nothing
      break;

      case ERROR_HANDLE_EOF:
      case ERROR_BROKEN_PIPE:
            // EOF
            reading_out = FALSE;
      break;

      default:
        // Other error
        cryptolens_set_error(e, CRYPTOLENS_ES_MC, 22, c);
        goto error;
      break;
      }
    }
  }

  c = cryptolens_buffer_check_size(&b_out);
  if (!c) { cryptolens_set_error(e, CRYPTOLENS_ES_MC, 100, 0); goto error; }

  b_out.b[b_out.p] = '\0';

  machine_code = (char *)malloc(65 * sizeof(char));
  if (!machine_code) { cryptolens_set_error(e, CRYPTOLENS_ES_MC, 23, 0); goto error; }

  SHA256(e, b_out.b, b_out.p, machine_code, 65);

  goto exit;

error:
  free(machine_code);
  machine_code = NULL;
exit:
  cryptolens_buffer_destroy(&b_out);
  cryptolens_buffer_destroy(&b_err);
  //CancelIoEx(p_out_read, NULL);
  //CancelIoEx(p_err_read, NULL);
  CloseHandle(child_process);
  CloseHandle(child_thread);
  CloseHandle(p_out_read);
  CloseHandle(p_err_read);


  return machine_code;
}

void
cryptolens_MC_destroy_machine_code(char * machine_code)
{
  free(machine_code);
}
