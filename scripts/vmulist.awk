#!/usr/bin/awk -f

BEGIN{
  FS="([ \t]+\\|+[ \t]+)|,|;"
  row="%s | %s | %8s | %8d | %s | %s | %s | %8s | %8d | %16s | %s\n"
}
NF >= 14 {
  vmudiff = $4 - channels[$7]
  oridiff = $10 - origins[$8]
  upi = $11
  if (index(upi, "*") > 0) {
    upi = "?"
  }
  printf(row, $1, $3, $4, vmudiff, $7, $8, $9, $10, oridiff, upi, $14)
  channels[$7] = $4
  origins[$8] = $10
}
