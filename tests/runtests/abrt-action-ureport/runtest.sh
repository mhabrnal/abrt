#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of abrt-action-ureport
#   Description: Verify abrt-action-ureport functionality
#   Author: Matej Habrnal <mhabrnal@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2014 Red Hat, Inc. All rights reserved.
#
#   This program is free software: you can redistribute it and/or
#   modify it under the terms of the GNU General Public License as
#   published by the Free Software Foundation, either version 3 of
#   the License, or (at your option) any later version.
#
#   This program is distributed in the hope that it will be
#   useful, but WITHOUT ANY WARRANTY; without even the implied
#   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
#   PURPOSE.  See the GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program. If not, see http://www.gnu.org/licenses/.
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

. /usr/share/beakerlib/beakerlib.sh
. ../aux/lib.sh

TEST="abrt-action-ureport"
PACKAGE="abrt"

rlJournalStart
    rlPhaseStartSetup
        check_prior_crashes

        LANG=""
        export LANG

        TmpDir=$(mktemp -d)
        cp -- fakefaf.py  "$TmpDir"
        pushd "$TmpDir"
    rlPhaseEnd

    rlPhaseStartTest "attaching contact email if configured"
        prepare
        generate_crash
        get_crash_path
        wait_for_hooks


        rlRun "augtool set /files/etc/libreport/plugins/ureport.conf/ContactEmail abrt@email.com" 0 "set ContactEmail settings to ureport.conf"
        rlRun "augtool set /files/etc/libreport/plugins/ureport.conf/URL http://127.0.0.1:12345/faf" 0 "set URL to ureport.conf"
        rlRun "echo 0 > $crash_PATH/ureports_counter" 0 "set ureports_counter to 0"

        ./fakefaf.py &> server.log &
        sleep 1

        pushd $crash_PATH
        /usr/libexec/abrt-action-ureport -vvv &> $TmpDir/ureport.log
        popd #$crash_PATH

        kill %1

        rlAssertGrep "curl: Connected to 127.0.0.1 (127.0.0.1) port 12345 (#0)" ureport.log
        rlAssertGrep "curl sent header: 'POST /faf/reports/new/ HTTP/1" ureport.log
        rlAssertGrep "curl sent header: 'POST /faf/reports/attach/ HTTP/1" ureport.log
        rlAssertGrep "Attaching ContactEmail: abrt@email.com" ureport.log
        rlAssertGrep "{ \"bthash\": \"691cf824e3e07457156125636e86c50279e29496\", \"type\": \"email\", \"data\": \"abrt@email.com\" }" ureport.log

        rlAssertGrep ".* - - \[.*\] \"POST /faf/reports/new/ HTTP/1.1\" 202 -" server.log
        rlAssertGrep ".* - - \[.*\] \"POST /faf/reports/attach/ HTTP/1.1\" 202 -" server.log

        rlRun "abrt-cli rm $crash_PATH" 0 "Remove crash dir"
    rlPhaseEnd

    rlPhaseStartTest "do not attach contact email if not configured"
        prepare
        generate_crash
        get_crash_path
        wait_for_hooks


        rlRun "augtool rm /files/etc/libreport/plugins/ureport.conf/ContactEmail" 0 "rm ContactEmail settings frim ureport.conf"
        rlRun "echo 0 > $crash_PATH/ureports_counter" 0 "set ureports_counter to 0"

        ./fakefaf.py &> server2.log &
        sleep 1

        pushd $crash_PATH
        /usr/libexec/abrt-action-ureport -vvv &> $TmpDir/ureport2.log
        popd # crash_PATH

        kill %1

        rlAssertGrep "curl: Connected to 127.0.0.1 (127.0.0.1) port 12345 (#0)" ureport2.log
        rlAssertGrep "curl sent header: 'POST /faf/reports/new/ HTTP/1" ureport2.log

        rlAssertNotGrep "Attaching ContactEmail: abrt@email.com" ureport2.log
        rlAssertNotGrep "curl sent header: 'POST /faf/reports/attach/ HTTP/1" ureport2.log
        rlAssertNotGrep "{ \"bthash\": \"691cf824e3e07457156125636e86c50279e29496\", \"type\": \"email\", \"data\": \"abrt@email.com\" }" ureport2.log

        rlAssertGrep ".* - - \[.*\] \"POST /faf/reports/new/ HTTP/1.1\" 202 -" server2.log
        rlAssertNotGrep ".* - - \[.*\] \"POST /faf/reports/attach/ HTTP/1.1\" 202 -" server2.log
        rlRun "abrt-cli rm $crash_PATH" 0 "Remove crash dir"
    rlPhaseEnd

    rlPhaseStartTest "uReport from unpackaged executable"
        prepare
        generate_crash
        get_crash_path
        wait_for_hooks

        rlRun "echo 0 > $crash_PATH/ureports_counter" 0 "set ureports_counter to 0"
        rlRun "rm -rf $crash_PATH/package $crash_PATH/pkg_*" 0 "remove package information"

        pushd $crash_PATH
        rlRun "/usr/libexec/abrt-action-ureport -vvv &> $TmpDir/ureport_unpackaged.log" 1
        popd # crash_PATH

        cat -n ureport_unpackaged.log
        rlAssertGrep "Problem comes from unpackaged executable. Unable to create uReport." ureport_unpackaged.log

        rlRun "abrt-cli rm $crash_PATH" 0 "Remove crash dir"
    rlPhaseEnd

    rlPhaseStartCleanup
        rlBundleLogs abrt $(ls server* ureport*)
        popd # TmpDir
        rm -rf -- "$TmpDir"
    rlPhaseEnd
    rlJournalPrintText
rlJournalEnd
