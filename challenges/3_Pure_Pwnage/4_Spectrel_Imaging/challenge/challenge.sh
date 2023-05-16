cd /data
bzip2 -df /data/submission.bz2
cd /challenge
echo $FLAG > flag.txt 
./ImagerScheduler < /data/submission > out
rm flag.txt 
bzip2 -zkf out
cp out.bz2 /data/
