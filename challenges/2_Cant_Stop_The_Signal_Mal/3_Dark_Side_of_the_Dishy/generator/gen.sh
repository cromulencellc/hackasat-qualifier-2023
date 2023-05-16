mkdir /dishy
python3 generate.py --flag $FLAG --loc /dishy
cd /dishy
tar cvzf dishy.tar.gz /dishy/*
cp /dishy/dishy.tar.gz /out

echo "\nUpload generated files:"
echo /dishy/dishy.tar.gz | /upload/upload.sh