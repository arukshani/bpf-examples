#! /bin/bash
#
# Copyright (c) 2017 Mellanox Technologies. All rights reserved.
#
# This Software is licensed under one of the following licenses:
#
# 1) under the terms of the "Common Public License 1.0" a copy of which is
#    available from the Open Source Initiative, see
#    https://urldefense.com/v3/__http://www.opensource.org/licenses/cpl.php__;!!Mih3wA!E0ciAR3JeSmn8fn4eWEalf3A3Kz-4J8-AT07_gky_31WhJLfX3LUtUtubgqq9fzrc2pnLypA-u_r9rmWrBI$ .
#
# 2) under the terms of the "The BSD License" a copy of which is
#    available from the Open Source Initiative, see
#    https://urldefense.com/v3/__http://www.opensource.org/licenses/bsd-license.php__;!!Mih3wA!E0ciAR3JeSmn8fn4eWEalf3A3Kz-4J8-AT07_gky_31WhJLfX3LUtUtubgqq9fzrc2pnLypA-u_rTa1U-9s$ .
#
# 3) under the terms of the "GNU General Public License (GPL) Version 2" a
#    copy of which is available from the Open Source Initiative, see
#    https://urldefense.com/v3/__http://www.opensource.org/licenses/gpl-license.php__;!!Mih3wA!E0ciAR3JeSmn8fn4eWEalf3A3Kz-4J8-AT07_gky_31WhJLfX3LUtUtubgqq9fzrc2pnLypA-u_r0cfUf9M$ .
#
# Licensee has the right to choose one of the above licenses.
#
# Redistributions of source code must retain the above copyright
# notice and one of the license notices.
#
# Redistributions in binary form must reproduce both the above copyright
# notice, one of the license notices in the documentation
# and/or other materials provided with the distribution.
#
if [ -z $1 ]; then
	echo "usage: $0 <interface or IB device> [show_cpu_number]"
	exit 1
fi

source common_irq_affinity.sh

IRQS=$( get_irq_list $1 )
if [ -z "$IRQS" ] ; then
        echo No IRQs found for $1.
        exit 1
fi

show_cpu=$2

for irq in $IRQS
do
	show_irq_affinity $irq $show_cpu
done

