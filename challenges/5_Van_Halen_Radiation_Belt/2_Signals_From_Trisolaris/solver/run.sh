cd /data/
tar xvzf Arecibo.tar.gz
cp bin/hip_main.dat /solver/
cp bin/de421.bsp /solver
cd /solver
python3 solver.py --hostname $CHAL_HOST --port $CHAL_PORT --filePath /data/bin