#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-user-cli
#   Description: PKI user-cert-show CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following ipa cli commands needs to be tested:
#  pki-user-cli-user-cert-show    Show the certs assigned to users in the pki ca subsystem.
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Roshni Pattath <rpattath@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2013 Red Hat, Inc. All rights reserved.
#
#   This copyrighted material is made available to anyone wishing
#   to use, modify, copy, or redistribute it subject to the terms
#   and conditions of the GNU General Public License version 2.
#
#   This program is distributed in the hope that it will be
#   useful, but WITHOUT ANY WARRANTY; without even the implied
#   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
#   PURPOSE. See the GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public
#   License along with this program; if not, write to the Free
#   Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
#   Boston, MA 02110-1301, USA.
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Include rhts environment
. /usr/bin/rhts-environment.sh
. /usr/share/beakerlib/beakerlib.sh
. /opt/rhqa_pki/rhcs-shared.sh
. /opt/rhqa_pki/pki-cert-cli-lib.sh
. /opt/rhqa_pki/env.sh

######################################################################################
#pki-user-cli-user-ca.sh should be first executed prior to pki-user-cli-user-add-ca.sh
#pki-user-cli-user-ca.sh should be first executed prior to pki-user-cli-user-cert-add-ca.sh
######################################################################################

########################################################################
# Test Suite Globals
########################################################################

########################################################################
user1=testuser1
user2=testuser2
user1fullname="Test user1"
user2fullname="Test user2"
user3=testuser3
user3fullname="Test user3"

run_pki-user-cli-user-cert-show-ca_tests(){

local cert_info="$TmpDir/cert_info"
##### pki_user_cli_user_cert_show_ca-configtest ####
     rlPhaseStartTest "pki_user_cli_user_cert-show-configtest-001: pki user-cert-show configuration test"
        rlRun "pki user-cert-show > $TmpDir/pki_user_cert_show_cfg.out" \
                1 \
                "User cert show configuration"
        rlAssertGrep "usage: user-cert-show <User ID> <Cert ID> \[OPTIONS...\]" "$TmpDir/pki_user_cert_show_cfg.out"
	rlAssertGrep "--encoded         Base-64 encoded" "$TmpDir/pki_user_cert_show_cfg.out"
        rlAssertGrep "--output <file>   Output file" "$TmpDir/pki_user_cert_show_cfg.out"
	rlAssertGrep "--pretty          Pretty print" "$TmpDir/pki_user_cert_show_cfg.out"
    rlPhaseEnd

	##### Tests to find certs assigned to CA users ####

	##### Show certs asigned to a user - valid Cert ID and User ID #####

	rlPhaseStartTest "pki_user_cli_user_cert-show-CA-002: Show certs assigned to a user - valid UserID and CertID"
                k=2	
        	rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            user-add --fullName=\"$user2fullname\" $user2"
		rlRun "generate_cert_cert_show $cert_info $k $user2 \"$user2fullname\"" 0  "Generating temp cert"
	        cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        	local STRIP_HEX_PKCS10=$(echo $cert_serialNumber | cut -dx -f2)
        	local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        	decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $user2 --input $TmpDir/pki_user_cert_show_CA_validcert_002.pem  > $TmpDir/pki_user_cert_show_CA_useraddcert_002.out" \
                            0 \
                            "Cert is added to the user $user2"
		rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\""
		rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" > $TmpDir/pki_user_cert_show_CA_usershowcert_002.out" \
			0 \
			"Show cert assigned to $user2"

		rlAssertGrep "Certificate \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=lab.eng.rdu.redhat.com Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\"" "$TmpDir/pki_user_cert_show_CA_usershowcert_002.out"
        	rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_CA_usershowcert_002.out"
        	rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_show_CA_usershowcert_002.out"
        	rlAssertGrep "Serial Number: $cert_serialNumber" "$TmpDir/pki_user_cert_show_CA_usershowcert_002.out"
        	rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_show_CA_usershowcert_002.out"
        	rlAssertGrep "Subject: UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_show_CA_usershowcert_002.out"

	rlPhaseEnd

	##### Show certs asigned to a user - invalid Cert ID #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-003: pki user-cert-show should fail if an invalid Cert ID is provided"
                
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"3;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\""
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"3;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" > $TmpDir/pki_user_cert_show_CA_usershowcert_003.out 2>&1" \
                        1 \
                        "Show cert assigned to user - Invalid Cert ID"
		rlAssertGrep "ResourceNotFoundException: No certificates found for $user2" "$TmpDir/pki_user_cert_show_CA_usershowcert_003.out"
	rlPhaseEnd

	##### Show certs asigned to a user - User does not exist #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-004: pki user-cert-show should fail if a non-existing User ID is provided"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show testuser4 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\""
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show testuser4 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" > $TmpDir/pki_user_cert_show_CA_usershowcert_004.out 2>&1" \
                        1 \
                        "Show cert assigned to user - User does not exist"
                rlAssertGrep "ResourceNotFoundException: User testuser4 not found" "$TmpDir/pki_user_cert_show_CA_usershowcert_004.out"
        rlPhaseEnd

	##### Show certs asigned to a user - User ID and Cert ID mismatch #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-005: pki user-cert-show should fail is there is a mismatch of User ID and Cert ID"
		rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            user-add --fullName=\"$user1fullname\" $user1"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user1 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\""
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user1 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" > $TmpDir/pki_user_cert_show_CA_usershowcert_005.out 2>&1" \
                        1 \
                        "Show cert assigned to user - User ID and Cert ID mismatch"
                rlAssertGrep "ResourceNotFoundException: No certificates found for $user1" "$TmpDir/pki_user_cert_show_CA_usershowcert_005.out"
        rlPhaseEnd

	##### Show certs asigned to a user - no User ID #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-006: pki user-cert-show should fail if User ID is not provided"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\""
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" > $TmpDir/pki_user_cert_show_CA_usershowcert_006.out 2>&1" \
                        1 \
                        "Show cert assigned to user - no User ID provided"
		rlAssertGrep "usage: user-cert-show <User ID> <Cert ID> \[OPTIONS...\]" "$TmpDir/pki_user_cert_show_CA_usershowcert_006.out"
	        rlAssertGrep "--encoded         Base-64 encoded" "$TmpDir/pki_user_cert_show_CA_usershowcert_006.out"
        	rlAssertGrep "--output <file>   Output file" "$TmpDir/pki_user_cert_show_CA_usershowcert_006.out"
	        rlAssertGrep "--pretty          Pretty print" "$TmpDir/pki_user_cert_show_CA_usershowcert_006.out"

        rlPhaseEnd

	##### Show certs asigned to a user - no Cert ID #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-007: pki user-cert-show should fail if Cert ID is not provided"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user1"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user1  > $TmpDir/pki_user_cert_show_CA_usershowcert_007.out 2>&1" \
                        1 \
                        "Show cert assigned to user - no Cert ID provided"
                rlAssertGrep "usage: user-cert-show <User ID> <Cert ID> \[OPTIONS...\]" "$TmpDir/pki_user_cert_show_CA_usershowcert_007.out"
                rlAssertGrep "--encoded         Base-64 encoded" "$TmpDir/pki_user_cert_show_CA_usershowcert_007.out"
                rlAssertGrep "--output <file>   Output file" "$TmpDir/pki_user_cert_show_CA_usershowcert_007.out"
                rlAssertGrep "--pretty          Pretty print" "$TmpDir/pki_user_cert_show_CA_usershowcert_007.out"

        rlPhaseEnd

	##### Show certs asigned to a user - --encoded option #####

	rlPhaseStartTest "pki_user_cli_user_cert-show-CA-008: Show certs assigned to a user - --encoded option - Valid Cert ID and User ID"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --encoded"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
			   -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --encoded > $TmpDir/pki_user_cert_show_CA_usershowcert_008.out" \
                        0 \
                        "Show cert assigned to user - --encoded option"
        rlPhaseEnd
	
	  ##### Show certs asigned to a user - --encoded option - no User ID #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-009: pki user-cert-show should fail if User ID is not provided with --encoded option"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --encoded"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --encoded > $TmpDir/pki_user_cert_show_CA_usershowcert_009.out 2>&1" \
                        1 \
                        "Show cert assigned to user - no User ID provided with --encoded option"
                rlAssertGrep "usage: user-cert-show <User ID> <Cert ID> \[OPTIONS...\]" "$TmpDir/pki_user_cert_show_CA_usershowcert_009.out"
                rlAssertGrep "--encoded         Base-64 encoded" "$TmpDir/pki_user_cert_show_CA_usershowcert_009.out"
                rlAssertGrep "--output <file>   Output file" "$TmpDir/pki_user_cert_show_CA_usershowcert_009.out"
                rlAssertGrep "--pretty          Pretty print" "$TmpDir/pki_user_cert_show_CA_usershowcert_009.out"

        rlPhaseEnd

        ##### Show certs asigned to a user - no Cert ID #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0010: pki user-cert-show should fail if Cert ID is not provided with --encoded option"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user1 --encoded"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user1 --encoded > $TmpDir/pki_user_cert_show_CA_usershowcert_0010.out 2>&1" \
                        1 \
                        "Show cert assigned to user - no Cert ID provided"
                rlAssertGrep "usage: user-cert-show <User ID> <Cert ID> \[OPTIONS...\]" "$TmpDir/pki_user_cert_show_CA_usershowcert_0010.out"
                rlAssertGrep "--encoded         Base-64 encoded" "$TmpDir/pki_user_cert_show_CA_usershowcert_0010.out"
                rlAssertGrep "--output <file>   Output file" "$TmpDir/pki_user_cert_show_CA_usershowcert_0010.out"
                rlAssertGrep "--pretty          Pretty print" "$TmpDir/pki_user_cert_show_CA_usershowcert_0010.out"

        rlPhaseEnd

	##### Show certs asigned to a user - --output <file> option ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0011: Show certs assigned to a user - --output <file> option - Valid Cert ID, User ID and file"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --output $TmpDir/pki_user_cert_show_CA_usercertshow_output.out"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
			   -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --output $TmpDir/pki_user_cert_show_CA_usercertshow_output.out > $TmpDir/pki_user_cert_show_CA_usershowcert_0011.out" \
                        0 \
                        "Show cert assigned to user - --output <file> option"
        rlPhaseEnd

	##### Show certs asigned to a user - --output <file> option - no User ID #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0012: pki user-cert-show should fail if User ID is not provided with --output <file> option"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --output $TmpDir/user_cert_show_output0012"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --output $TmpDir/user_cert_show_output0012 > $TmpDir/pki_user_cert_show_CA_usershowcert_0012.out 2>&1" \
                        1 \
                        "Show cert assigned to user - no User ID provided with --output option"
                rlAssertGrep "usage: user-cert-show <User ID> <Cert ID> \[OPTIONS...\]" "$TmpDir/pki_user_cert_show_CA_usershowcert_0012.out"
                rlAssertGrep "--encoded         Base-64 encoded" "$TmpDir/pki_user_cert_show_CA_usershowcert_0012.out"
                rlAssertGrep "--output <file>   Output file" "$TmpDir/pki_user_cert_show_CA_usershowcert_0012.out"
                rlAssertGrep "--pretty          Pretty print" "$TmpDir/pki_user_cert_show_CA_usershowcert_0012.out"

        rlPhaseEnd

        ##### Show certs asigned to a user - --output <file> option - no Cert ID #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0013: pki user-cert-show should fail if Cert ID is not provided with --output <file> option"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user1 --output $TmpDir/user_cert_show_output0013"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user1 --output $TmpDir/user_cert_show_output0013 > $TmpDir/pki_user_cert_show_CA_usershowcert_0013.out 2>&1" \
                        1 \
                        "Show cert assigned to user - no Cert ID provided"
                rlAssertGrep "usage: user-cert-show <User ID> <Cert ID> \[OPTIONS...\]" "$TmpDir/pki_user_cert_show_CA_usershowcert_0013.out"
                rlAssertGrep "--encoded         Base-64 encoded" "$TmpDir/pki_user_cert_show_CA_usershowcert_0013.out"
                rlAssertGrep "--output <file>   Output file" "$TmpDir/pki_user_cert_show_CA_usershowcert_0013.out"
                rlAssertGrep "--pretty          Pretty print" "$TmpDir/pki_user_cert_show_CA_usershowcert_0013.out"

        rlPhaseEnd

	##### Show certs asigned to a user - --output <file> option - Directory does not exist #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0014: pki user-cert-show should fail if --output <file> directory does not exist"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --output /tmp/tmpDir/user_cert_show_output0014"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --output /tmp/tmpDir/user_cert_show_output0014 > $TmpDir/pki_user_cert_show_CA_usershowcert_0014.out 2>&1" \
                        1 \
                        "Show cert assigned to user - directory does not exist"

        rlPhaseEnd

	##### Show certs asigned to a user - --output <file> option - without <file> argument #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0015: pki user-cert-show should fail if --output option <file argument is not provided "
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --output"                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --output > $TmpDir/pki_user_cert_show_CA_usershowcert_0015.out 2>&1" \
                        1 \
                        "Show cert assigned to user - --output option <file> argument is not provided"

        rlPhaseEnd
	##### Show certs asigned to a user - --pretty option ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0016: Show certs assigned to a user - --pretty option - Valid Cert ID, User ID"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --pretty"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
			   -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --pretty > $TmpDir/pki_user_cert_show_CA_usershowcert_0016.out" \
                        0 \
                        "Show cert assigned to user - --pretty option"
        rlPhaseEnd

        ##### Show certs asigned to a user - --pretty option - no User ID #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0017: pki user-cert-show should fail if User ID is not provided with --pretty option"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --pretty"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --pretty > $TmpDir/pki_user_cert_show_CA_usershowcert_0017.out 2>&1" \
                        1 \
                        "Show cert assigned to user - no User ID provided with --pretty option"
                rlAssertGrep "usage: user-cert-show <User ID> <Cert ID> \[OPTIONS...\]" "$TmpDir/pki_user_cert_show_CA_usershowcert_0017.out"
                rlAssertGrep "--encoded         Base-64 encoded" "$TmpDir/pki_user_cert_show_CA_usershowcert_0017.out"
                rlAssertGrep "--output <file>   Output file" "$TmpDir/pki_user_cert_show_CA_usershowcert_0017.out"
                rlAssertGrep "--pretty          Pretty print" "$TmpDir/pki_user_cert_show_CA_usershowcert_0017.out"

        rlPhaseEnd

        ##### Show certs asigned to a user - --pretty option - no Cert ID #####

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0018: pki user-cert-show should fail if Cert ID is not provided with --pretty option"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user1 --pretty"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user1 --pretty > $TmpDir/pki_user_cert_show_CA_usershowcert_0018.out 2>&1" \
                        1 \
                        "Show cert assigned to user - no Cert ID provided"
                rlAssertGrep "usage: user-cert-show <User ID> <Cert ID> \[OPTIONS...\]" "$TmpDir/pki_user_cert_show_CA_usershowcert_0018.out"
                rlAssertGrep "--encoded         Base-64 encoded" "$TmpDir/pki_user_cert_show_CA_usershowcert_0018.out"
                rlAssertGrep "--output <file>   Output file" "$TmpDir/pki_user_cert_show_CA_usershowcert_0018.out"
                rlAssertGrep "--pretty          Pretty print" "$TmpDir/pki_user_cert_show_CA_usershowcert_0018.out"

        rlPhaseEnd

	##### Show certs asigned to a user - --pretty, --encoded and --output options ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0019: Show certs assigned to a user - --pretty, --encoded and --output options - Valid Cert ID, User ID and file"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --encoded --pretty --output $TmpDir/user_cert_show_output0019"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
			   -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" --encoded --pretty --output $TmpDir/user_cert_show_output0019 > $TmpDir/pki_user_cert_show_CA_usershowcert_0019.out" \
                        0 \
                        "Show cert assigned to user - --pretty, --output and --encoded options"
        rlPhaseEnd

	##### Show certs asigned to a user - as CA_agentV ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0020: Show certs assigned to a user - as CA_agentV"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_agentV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\""
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_agentV \
			   -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" > $TmpDir/pki_user_cert_show_CA_usershowcert_0020.out" \
                        0 \
                        "Show cert assigned to user - as CA_agentV"
        rlPhaseEnd

	##### Show certs asigned to a user - as CA_auditorV ##### 

        rlPhaseStartTest "pki_user_cli_user_cert-show-CA-0021: Show certs assigned to a user - as CA_auditorV"
                rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n CA_auditorV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\""
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_auditorV \
			   -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-show $user2 \"2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2,E=$user2@example.org,CN=$user2fullname,OU=Engineering,O=Example,C=US\" > $TmpDir/pki_user_cert_show_CA_usershowcert_0021.out" \
                        0 \
                        "Show cert assigned to user - as CA_auditorV"
        rlPhaseEnd
}

generate_cert_cert_show()
{

                local reqstatus
                local requestid
                local requestdn
                local CERT_INFO="$1"
                local file_no="$2"
                local user_id="$3"
                local userfullname="$4"
                local ext=".out"
                local cert_ext=".pem"
                if [ "$user_id" = "Örjan Äke" ] ; then
                        rlRun "create_cert_request $CERTDB_DIR redhat123 pkcs10 rsa 2048 \"Örjan Äke\" \"Örjan Äke\" "test@example.org" "Engineering" "Example" "US" "--" "reqstatus" "requestid" "requestdn""
                else
                        rlRun "create_cert_request $CERTDB_DIR redhat123 pkcs10 rsa 2048 \"$userfullname\" "$user_id" "$user_id@example.org" "Engineering" "Example" "US" "--" "reqstatus" "requestid" "requestdn""
                fi

                rlRun "pki cert-request-show $requestid > $TmpDir/pki_user_cert_show_CA_certrequestshow_00$file_no$ext" 0 "Executing pki cert-request-show $requestid"
                rlAssertGrep "Request ID: $requestid" "$TmpDir/pki_user_cert_show_CA_certrequestshow_00$file_no$ext"
                rlAssertGrep "Type: enrollment" "$TmpDir/pki_user_cert_show_CA_certrequestshow_00$file_no$ext"
                rlAssertGrep "Status: pending" "$TmpDir/pki_user_cert_show_CA_certrequestshow_00$file_no$ext"
                rlAssertGrep "Operation Result: success" "$TmpDir/pki_user_cert_show_CA_certrequestshow_00$file_no$ext"

                #Agent Approve the certificate after reviewing the cert for the user
                rlLog "Executing: pki -d $CERTDB_DIR/ \
                                      -n CA_agentV \
                                      -c $CERTDB_DIR_PASSWORD \
                                      -t ca \
                                      cert-request-review --action=approve $requestid"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_agentV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                           cert-request-review --action=approve $requestid > $TmpDir/pki_user_cert_show_CA_certapprove_00$file_no$ext" \
                           0 \
                           "CA agent approve the cert"
                rlAssertGrep "Approved certificate request $requestid" "$TmpDir/pki_user_cert_show_CA_certapprove_00$file_no$ext"
                rlRun "pki cert-request-show $requestid > $TmpDir/pki_user_cert_show_CA_certapprovedshow_00$file_no$ext" 0 "Executing pki cert-request-show $requestid"
                rlAssertGrep "Request ID: $requestid" "$TmpDir/pki_user_cert_show_CA_certapprovedshow_00$file_no$ext"
                rlAssertGrep "Type: enrollment" "$TmpDir/pki_user_cert_show_CA_certapprovedshow_00$file_no$ext"
                rlAssertGrep "Status: complete" "$TmpDir/pki_user_cert_show_CA_certapprovedshow_00$file_no$ext"
                rlAssertGrep "Certificate ID:" "$TmpDir/pki_user_cert_show_CA_certapprovedshow_00$file_no$ext"
                local certificate_serial_number=`cat $TmpDir/pki_user_cert_show_CA_certapprovedshow_00$file_no$ext | grep "Certificate ID:" | awk '{print $3}'`
                rlLog "Cerificate Serial Number=$certificate_serial_number"
                #Verify the certificate is valid
                rlRun "pki cert-show  $certificate_serial_number --encoded > $TmpDir/pki_user_cert_show_CA_certificate_show_00$file_no$ext" 0 "Executing pki cert-show $certificate_serial_number"

                rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_show_CA_certificate_show_00$file_no$ext > $TmpDir/pki_user_cert_show_CA_validcert_00$file_no$cert_ext"
                 rlRun "certutil -d $CERTDB_DIR -A -n \"$user_id\" -i $TmpDir/pki_user_cert_show_CA_validcert_00$file_no$cert_ext  -t "u,u,u""
                echo cert_serialNumber-$certificate_serial_number > $CERT_INFO
                echo cert_requestdn-$requestdn >> $CERT_INFO
                return 0;
}

