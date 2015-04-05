#!/bin/bash
TFILE=test/temp.java


function test_data_safe_crypto_algo()
{
	echo "test_data_safe_crypto_algo ..."
	for f in test/*.c; 
	do
		cp $f $TFILE
		./data_safe_crypto_algo_test enc 1234abcdASDF $TFILE
		STR=`cmp $f $TFILE`
		if [ "$?" = "0" ]
		then
			echo "encrypted failed."
		fi
		./data_safe_crypto_algo_test dec 1234abcdASDF $TFILE
		cmp $f $TFILE
	done
}

function test_datasafe_crypto()
{
	echo "test_datasafe_crypto ..."
	for f in test/*.c; 
	do
		echo $f
		cp $f $TFILE
		STR=`./datasafe_encrypt $TFILE`
		STR=`cmp $f $TFILE`
		if [ "$?" = "0" ]
		then
			echo "encrypted failed."
		fi
		STR=`./datasafe_decrypt --user=admin --passwd=12345678 $TFILE`
		cmp $f $TFILE
	done

	./datasafe_encrypt test/dirs
	./datasafe_decrypt --user=admin --passwd=12345678 test/dirs

	return;
}

function test_datasafe_admin()
{
	for i in 1 2 3 4 5 5 6 7 8 9
	do
		./datasafe_admin --passwd=12345678 --action=adduser --args=lixianjing
		./datasafe_admin --passwd=12345678 --action=changepasswd --args=lixianjing:12345678
		./datasafe_admin --passwd=12345678 --action=deluser --args=lixianjing
		./datasafe_admin --passwd=12345678 --action=getpolicy --args=none
		./datasafe_admin --passwd=12345678 --action=setpolicy --args=policy.txt
	done
}

function run_datasafe_test()
{
	for i in 1 2 3 4 5 5 6 7 8 9
	do
		rm -f /tmp/apkg.tar.gz
		./datasafe_test
		STR=`cmp /tmp/apkg.tar.gz /etc/datasafe/apkg.tar.gz`
		if [ "$?" = "0" ]
		then
			echo "download apkg.tar.gz ok."
		fi
	done
}

./datasafe_admin --passwd=brnADMIN --action=changepasswd --args=admin:12345678
#test_data_safe_crypto_algo
test_datasafe_crypto
#test_datasafe_admin
#run_datasafe_test
./datasafe_admin --passwd=12345678 --action=changepasswd --args=admin:brnADMIN
