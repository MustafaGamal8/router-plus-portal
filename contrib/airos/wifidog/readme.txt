-- Compiling airos with the router-plus-portal package running at boot

Because airos doesn't have a package manager like opkf and has a (mostly) read-only file system, we need to build the the firmware with router-plus-portal in it to have router-plus-portal running on airos

1- Get the latest router-plus-portal source code tarball from sourceforge (http://sourceforge.net/projects/router-plus-portal/files/) and copy it to the ~/dev/router-plus-portal directory

2- Get the router-plus-portal airos package directory

cd ~/dev/router-plus-portal
wget http://dev.router-plus-portal.org/wiki/doc/install/airos/router-plus-portal_airos.tar.gz
tar xvzf router-plus-portal_airos.tar.gz

If compiling from source, this directory is located in router-plus-portal/contrib/airos

3- Download the airos SDK from http://www.ubnt.com/support/downloads and copy it to the ~/dev/airos directory

4- Untar the SDK and prepare the files

cd ~/dev/airos
tar xvjf SDK.UBNT.v5.2.tar.bz2
cd SDK.UBNT.v5.2

cd openwrt/package
ln -s ~/dev/router-plus-portal/airos/router-plus-portal/ 
cd ../dl
ln -s ~/dev/router-plus-portal/router-plus-portal-20090925.tar.gz

cd ../..
patch -p1 < openwrt/package/router-plus-portal/files.patch

5- Prepare the router-plus-portal.conf file for your network, since airos is readonly, changes to the config files cannot be done in the router

cd ~/dev/airos/SDK.UBNT.v5.2/openwrt
mkdir -p files/usr/etc
cp package/router-plus-portal/files/router-plus-portal.conf files/usr/etc/router-plus-portal.conf

6- Edit the files/usr/etc/router-plus-portal.conf file for your authentication server settings.  Also the GatewayInterface may need to be changed if you are not using a SOHO router configuration (eth0 for SOHO router, ath0 for router)

7- Make the os

make world V=99

8- Your new image should be available in the openwrt/bin directory as XM.v5.2....bin
