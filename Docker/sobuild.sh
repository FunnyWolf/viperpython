cd /root/viper/Msgrpc
python3.7 setup.py build_ext
mv ./build/lib.linux-x86_64-3.7/Msgrpc/msgrpc.cpython-37m-x86_64-linux-gnu.so .
rm ./msgrpc.c
rm ./msgrpc.py
rm -rf ./__pycache__/
rm -rf ./build/

cd /root/viper/Core
python3.7 setup.py build_ext
mv ./build/lib.linux-x86_64-3.7/Core/core.cpython-37m-x86_64-linux-gnu.so .
rm ./core.c
rm ./core.py
rm -rf ./__pycache__/
rm -rf ./build/

cd /root/viper/PostLateral
python3.7 setup.py build_ext
mv ./build/lib.linux-x86_64-3.7/PostLateral/postlateral.cpython-37m-x86_64-linux-gnu.so .
rm ./postlateral.c
rm ./postlateral.py
rm -rf ./__pycache__/
rm -rf ./build/

cd /root/viper/PostModule
python3.7 setup.py build_ext
mv ./build/lib.linux-x86_64-3.7/PostModule/postmodule.cpython-37m-x86_64-linux-gnu.so .
rm ./postmodule.c
rm ./postmodule.py
rm -rf ./__pycache__/
rm -rf ./build/
