/*
pseudo code :
printf("%p, %p \n",auth,service);
input = fgets(buffer,128,stdin);
if strncmp(buffer, "auth ", 5) == 0
{
auth = calloc(sizeof char, 4)
str = buffer + 5;
strlen(str);
if len < 31 : strcpy(auth, str);
}
if strncmp(buffer, "reset", 5) == 0 : free(str)
if strncmp(buffer, "service", 7) == 0 : service = strdup
if strncp(login) : if auth + 32 == NULL : fwrite password; else /bin/sh
*/

int main(void)
{
  char cVar1;
  char *pcVar2;
  char *pcVar3;
  char *input;
  int i;
  uint uVar6;
  byte *buffer_ptr;
  byte *str_auth;
  bool if_inf_addr_buffer_n_auth;
  undefined1 uVar10;
  undefined1 uVar11;
  undefined1 uVar12;
  bool if_equal_addr_buffer_n_auth;
  undefined1 uVar14;
  byte bVar15;
  byte buffer [5];
  char local_8b [2];
  char acStack_89 [125];
  
  bVar15 = 0;
  do {
    printf("%p, %p \n",auth,service);
    input = fgets((char *)buffer,0x80,stdin);
    if_inf_addr_buffer_n_auth = false;
    if (input == (char *)0x0) {
      return 0;
    }
    i = 5;
    if_equal_addr_buffer_n_auth = false;
    buffer_ptr = buffer;
    str_auth = "auth ";
    do {
      if (i == 0) break;
      i = i + -1;
      if_inf_addr_buffer_n_auth = *buffer_ptr < *str_auth;
      if_equal_addr_buffer_n_auth = *buffer_ptr == *str_auth;
      buffer_ptr = buffer_ptr + (uint)bVar15 * -2 + 1;
      str_auth = str_auth + (uint)bVar15 * -2 + 1;
    } while (if_equal_addr_buffer_n_auth);
    uVar10 = 0;
    uVar14 = 0;
    if ((!if_inf_addr_buffer_n_auth && !if_equal_addr_buffer_n_auth) == if_inf_addr_buffer_n_auth) {
      auth = malloc(4);
      input = auth + 1;
      pcVar2 = auth + 2;
      pcVar3 = auth + 3;
      auth[0] = '\0';
      *input = '\0';
      *pcVar2 = '\0';
      *pcVar3 = '\0';
      uVar6 = 0xffffffff;
      input = local_8b;
      do {
        if (uVar6 == 0) break;
        uVar6 = uVar6 - 1;
        cVar1 = *input;
        input = input + (uint)bVar15 * -2 + 1;
      } while (cVar1 != '\0');
      uVar6 = ~uVar6 - 1;
      uVar10 = uVar6 < 0x1e;
      uVar14 = uVar6 == 0x1e;
      if (uVar6 < 0x1f) {
        strcpy(auth,local_8b);
      }
    }
    i = 5;
    buffer_ptr = buffer;
    pbVar8 = (byte *)"reset";
    do {
      if (i == 0) break;
      i = i + -1;
      uVar10 = *buffer_ptr < *pbVar8;
      uVar14 = *buffer_ptr == *pbVar8;
      buffer_ptr = buffer_ptr + (uint)bVar15 * -2 + 1;
      pbVar8 = pbVar8 + (uint)bVar15 * -2 + 1;
    } while ((bool)uVar14);
    uVar11 = 0;
    uVar14 = (!(bool)uVar10 && !(bool)uVar14) == (bool)uVar10;
    if ((bool)uVar14) {
      free(auth);
    }
    i = 6;
    buffer_ptr = buffer;
    pbVar8 = (byte *)"service";
    do {
      if (i == 0) break;
      i = i + -1;
      uVar11 = *buffer_ptr < *pbVar8;
      uVar14 = *buffer_ptr == *pbVar8;
      buffer_ptr = buffer_ptr + (uint)bVar15 * -2 + 1;
      pbVar8 = pbVar8 + (uint)bVar15 * -2 + 1;
    } while ((bool)uVar14);
    uVar12 = 0;
    uVar10 = 0;
    if ((!(bool)uVar11 && !(bool)uVar14) == (bool)uVar11) {
      uVar12 = (byte *)0xfffffff8 < buffer;
      uVar10 = acStack_89 == (char *)0x0;
      service = strdup(acStack_89);
    }
    i = 5;
    buffer_ptr = buffer;
    pbVar8 = (byte *)"login";
    do {
      if (i == 0) break;
      i = i + -1;
      uVar12 = *buffer_ptr < *pbVar8;
      uVar10 = *buffer_ptr == *pbVar8;
      buffer_ptr = buffer_ptr + (uint)bVar15 * -2 + 1;
      pbVar8 = pbVar8 + (uint)bVar15 * -2 + 1;
    } while ((bool)uVar10);
    if ((!(bool)uVar12 && !(bool)uVar10) == (bool)uVar12) {
      if (*(int *)(auth + 0x20) == 0) {
        fwrite("Password:\n",1,10,stdout);
      }
      else {
        system("/bin/sh");
      }
    }
  } while( true );
  return 0;
}