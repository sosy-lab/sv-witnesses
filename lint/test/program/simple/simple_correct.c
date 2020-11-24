void reach_error(){}
int main() {
  int i = 0;
  while (i<10) {
    i++;
  }
  if (i<10) {
    reach_error();
  }
  return 0;
}
