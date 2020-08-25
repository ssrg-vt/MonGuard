#!/bin/bash
### We should print .text .data .bss [addr, size]
#echo "Use:     (sudo) ./checker.sh binary "

bin=$1
rm -rf /tmp/dec.info

echo "Create /tmp/dec.info file ..."
tmpfile=$(tempfile -n /tmp/dec.info) || exit
echo "File" $tmpfile "created"

## dump the sections first
result=$(readelf -SW $bin | grep " .text" | python elf-section.py)
echo ".text:" $result
echo $result > $tmpfile
## use " .data " to avoid finding out ".rodata" and ".data.rel.ro"
result=$(readelf -SW $bin | grep " .data " | python elf-section.py)
echo ".data:" $result
echo $result >> $tmpfile
result=$(readelf -SW $bin | grep " .bss"  | python elf-section.py)
echo " .bss:" $result
echo $result >> $tmpfile
result=$(readelf -SW $bin | grep " .plt "  | python elf-section.py)
echo " .plt:" $result
echo $result >> $tmpfile
result=$(readelf -SW $bin | grep " .got.plt"  | python elf-section.py)
echo " .got.plt:" $result
echo $result >> $tmpfile

echo "Verify: cat "$tmpfile
cat $tmpfile
