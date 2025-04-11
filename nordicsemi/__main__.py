#
# Copyright (c) 2016 Nordic Semiconductor ASA
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#   1. Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
#   2. Redistributions in binary form must reproduce the above copyright notice, this
#   list of conditions and the following disclaimer in the documentation and/or
#   other materials provided with the distribution.
#
#   3. Neither the name of Nordic Semiconductor ASA nor the names of other
#   contributors to this software may be used to endorse or promote products
#   derived from this software without specific prior written permission.
#
#   4. This software must only be used in or with a processor manufactured by Nordic
#   Semiconductor ASA, or in or with a processor manufactured by a third party that
#   is used in combination with a processor manufactured by Nordic Semiconductor.
#
#   5. Any software provided in binary or object form under this license must not be
#   reverse engineered, decompiled, modified and/or disassembled.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

"""nrfutil command line tool."""
import os
import sys
import click
import time
import logging
import re
sys.path.append(os.getcwd())

from nordicsemi.dfu.bl_dfu_sett import BLDFUSettings
from nordicsemi.dfu.dfu import Dfu
from nordicsemi.dfu.dfu_transport import DfuEvent, TRANSPORT_LOGGING_LEVEL
from nordicsemi.dfu.dfu_transport_serial import DfuTransportSerial
from nordicsemi.dfu.package import Package
from nordicsemi import version as nrfutil_version
from nordicsemi.dfu.signing import Signing
from pc_ble_driver_py.exceptions import NordicSemiException
from nordicsemi.lister.device_lister import DeviceLister

logger = logging.getLogger(__name__)

def ble_driver_init(conn_ic_id):
    global BLEDriver, Flasher, DfuTransportBle, config
    from pc_ble_driver_py import config
    config.__conn_ic_id__ = conn_ic_id
    from pc_ble_driver_py.ble_driver    import BLEDriver, Flasher
    from nordicsemi.dfu.dfu_transport_ble import DfuTransportBle

def display_sec_warning():
    default_key_warning = """
|===============================================================|
|##      ##    ###    ########  ##    ## #### ##    ##  ######  |
|##  ##  ##   ## ##   ##     ## ###   ##  ##  ###   ## ##    ## |
|##  ##  ##  ##   ##  ##     ## ####  ##  ##  ####  ## ##       |
|##  ##  ## ##     ## ########  ## ## ##  ##  ## ## ## ##   ####|
|##  ##  ## ######### ##   ##   ##  ####  ##  ##  #### ##    ## |
|##  ##  ## ##     ## ##    ##  ##   ###  ##  ##   ### ##    ## |
| ###  ###  ##     ## ##     ## ##    ## #### ##    ##  ######  |
|===============================================================|
|The security key you provided is insecure, as it part of a     |
|known set of keys that have been widely distributed. Do NOT use|
|it in your final product or your DFU procedure may be          |
|compromised and at risk of malicious attacks.                  |
|===============================================================|
"""
    click.echo("{}".format(default_key_warning))

def display_nokey_warning():
    default_nokey_warning = """
|===============================================================|
|##      ##    ###    ########  ##    ## #### ##    ##  ######  |
|##  ##  ##   ## ##   ##     ## ###   ##  ##  ###   ## ##    ## |
|##  ##  ##  ##   ##  ##     ## ####  ##  ##  ####  ## ##       |
|##  ##  ## ##     ## ########  ## ## ##  ##  ## ## ## ##   ####|
|##  ##  ## ######### ##   ##   ##  ####  ##  ##  #### ##    ## |
|##  ##  ## ##     ## ##    ##  ##   ###  ##  ##   ### ##    ## |
| ###  ###  ##     ## ##     ## ##    ## #### ##    ##  ######  |
|===============================================================|
|You are not providing a signature key, which means the DFU     |
|files will not be signed, and are vulnerable to tampering.     |
|This is only compatible with a signature-less bootloader and is|
|not suitable for production environments.                      |
|===============================================================|
"""
    click.echo("{}".format(default_nokey_warning))

def display_debug_warning():
    debug_warning = """
|===============================================================|
|##      ##    ###    ########  ##    ## #### ##    ##  ######  |
|##  ##  ##   ## ##   ##     ## ###   ##  ##  ###   ## ##    ## |
|##  ##  ##  ##   ##  ##     ## ####  ##  ##  ####  ## ##       |
|##  ##  ## ##     ## ########  ## ## ##  ##  ## ## ## ##   ####|
|##  ##  ## ######### ##   ##   ##  ####  ##  ##  #### ##    ## |
|##  ##  ## ##     ## ##    ##  ##   ###  ##  ##   ### ##    ## |
| ###  ###  ##     ## ##     ## ##    ## #### ##    ##  ######  |
|===============================================================|
|You are generating a package with the debug bit enabled in the |
|init packet. This is only compatible with a debug bootloader   |
|and is not suitable for production.                            |
|===============================================================|
"""
    click.echo("{}".format(debug_warning))

def display_settings_backup_warning():
    debug_warning = """
Note: Generating a DFU settings page with backup page included.
This is only required for bootloaders from nRF5 SDK 15.1 and newer.
If you want to skip backup page generation, use --no-backup option."""
    click.echo("{}".format(debug_warning))

def int_as_text_to_int(value):
    try:
        if value[:2].lower() == '0x':
            return int(value[2:], 16)
        elif value[:1] == '0':
            return int(value, 8)
        return int(value, 10)
    except ValueError:
        raise NordicSemiException('%s is not a valid integer' % value)

# TODO: Create query function that maps query-result strings with functions
def query_func(question, default=False):
    """
    Ask a string question
    No input defaults to "no" which results in False
    """
    valid = {"yes": True, "y": True, "no": False, "n": False}
    if default is True:
        prompt = " [Y/n]"
    else:
        prompt = " [y/N]"

    while True:
        print("%s %s" % (question, prompt))
        choice = input().lower()
        if choice == '':
            return default
        elif choice in valid:
            return valid[choice]
        else:
            print("Please respond with y/n")

def pause():
    while True:
        try:
            input()
        except (KeyboardInterrupt, EOFError):
            break

class BasedIntOrNoneParamType(click.ParamType):
    name = 'Integer'

    def convert(self, value, param, ctx):
        try:
            if value.lower() == 'none':
                return 'none'
            return int_as_text_to_int(value)
        except NordicSemiException:
            self.fail('%s is not a valid integer' % value, param, ctx)

BASED_INT_OR_NONE = BasedIntOrNoneParamType()

class BasedIntParamType(BasedIntOrNoneParamType):
    name = 'Integer'

BASED_INT = BasedIntParamType()

class TextOrNoneParamType(click.ParamType):
    name = 'Text'

    def convert(self, value, param, ctx):
        return value

TEXT_OR_NONE = TextOrNoneParamType()

BOOT_VALIDATION_ARGS = [
    'NO_VALIDATION',
    'VALIDATE_GENERATED_CRC',
    'VALIDATE_GENERATED_SHA256',
    'VALIDATE_ECDSA_P256_SHA256',
]
DEFAULT_BOOT_VALIDATION = 'VALIDATE_GENERATED_CRC'

KEY_CHOICE = ['pk', 'sk']
KEY_FORMAT = [
    'hex',
    'code',
    'pem',
    'dbgcode',
]


class OptionRequiredIf(click.Option):

    def full_process_value(self, ctx, value):
        value = super().full_process_value(ctx, value)
        if ('serial_number' not in ctx.params or not ctx.params['serial_number']) and value is None:
            msg = 'Required if "-snr" / "--serial-number" is not defined.'
            raise click.MissingParameter(ctx=ctx, param=self, message=msg)
        return value

@click.group()
@click.option('-v', '--verbose',
              help='Increase verbosity of output. Can be specified more than once (up to -v -v -v -v).',
              count=True)
@click.option('-o', '--output',
              help='Log output to file',
              metavar='<filename>')
def cli(verbose, output):
    #click.echo('verbosity: %s' % verbose)
    if verbose == 0:
        log_level = logging.ERROR
    elif verbose == 1:
        log_level = logging.WARNING
    elif verbose == 2:
        log_level = logging.INFO
    elif verbose == 3:
        log_level = logging.DEBUG
    else:
        # Custom level, logs all the bytes sent/received over the wire/air
        log_level = TRANSPORT_LOGGING_LEVEL

    logging.basicConfig(format='%(asctime)s %(message)s', level=log_level)

    if (output):
        root = logging.getLogger('')
        fh = logging.FileHandler(output)
        fh.setLevel(log_level)
        fh.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
        root.addHandler(fh)

@cli.command()
def version():
    """Display nrfutil version."""
    click.echo("nrfutil version {}".format(nrfutil_version.NRFUTIL_VERSION))
    logger.info("PyPi URL: https://pypi.python.org/pypi/nrfutil")
    logger.debug("GitHub URL: https://github.com/NordicSemiconductor/pc-nrfutil")

@cli.group(short_help='Generate and display Bootloader DFU settings.')
def settings():
    """
    This set of commands supports creating and displaying bootloader settings.
    """
    pass

@settings.command(short_help='Generate a .hex file with Bootloader DFU settings.')
@click.argument('hex_file', required=True, type=click.Path())
@click.option('--family',
              help='nRF IC family: NRF51 or NRF52 or NRF52QFAB or NRF52810 or NRF52840',
              type=click.Choice(['NRF51', 'NRF52', 'NRF52QFAB', 'NRF52810', 'NRF52840']),
              required=True)
@click.option('--application',
              help='The application firmware file. This can be omitted if'
                    'the target IC does not contain an application in flash.'
                    'Requires --application-version or --application-version-string.',
              type=click.STRING)
@click.option('--application-version',
              help='The application version.',
              type=BASED_INT_OR_NONE)
@click.option('--application-version-string',
              help='The application version string, e.g. "2.7.31". Will be converted to an integer, e.g. 20731.',
              type=click.STRING)
@click.option('--bootloader-version',
              help='The bootloader version.',
              type=BASED_INT_OR_NONE,
              required=True)
@click.option('--bl-settings-version',
              help='The Bootloader settings version.'
              'Defined in nrf_dfu_types.h, the following apply to released SDKs:'
              '\n|SDK12.0.0 - SDK15.2.0|1|'
              '\n|SDK15.3.0 -          |2|',
              type=BASED_INT_OR_NONE,
              required=True)
@click.option('--start-address',
              help='Custom start address for the settings page. If not specified, '
                   'then the last page of the flash is used.',
              type=BASED_INT_OR_NONE)
@click.option('--no-backup',
              help='Do not overwrite DFU settings backup page. If not specified, '
                   'than the resulting .hex file will contain a copy of DFU settings, '
                   'that will overwrite contents of DFU settings backup page.',
              type=click.BOOL,
              is_flag=True,
              required=False)
@click.option('--backup-address',
              help='Address of the DFU settings backup page inside flash. '
                   'By default, the backup page address is placed one page below DFU settings. '
                   'The value is precalculated based on configured settings address '
                   '(<DFU_settings_address> - 0x1000).',
              type=BASED_INT_OR_NONE)
@click.option('--app-boot-validation',
              help='The method of boot validation for application.',
              required=False,
              type=click.Choice(BOOT_VALIDATION_ARGS))
@click.option('--sd-boot-validation',
              help='The method of boot validation for SoftDevice.',
              required=False,
              type=click.Choice(BOOT_VALIDATION_ARGS))
@click.option('--softdevice',
              help='The SoftDevice firmware file. Must be given if SD Boot Validation is used.',
              required=False,
              type=click.Path(exists=True, resolve_path=True, file_okay=True, dir_okay=False))
@click.option('--key-file',
              help='The private (signing) key in PEM format. Needed for ECDSA Boot Validation.',
              required=False,
              type=click.Path(exists=True, resolve_path=True, file_okay=True, dir_okay=False))
def generate(hex_file,
             family,
             application,
             application_version,
             application_version_string,
             bootloader_version,
             bl_settings_version,
             start_address,
             no_backup,
             backup_address,
             app_boot_validation,
             sd_boot_validation,
             softdevice,
             key_file):

    # The user can specify the application version with two different
    # formats. As an integer, e.g. 102130, or as a string
    # "10.21.30". Internally we convert to integer.
    if application_version_string:
        application_version_internal = convert_version_string_to_int(application_version_string)
        if application_version:
            click.echo('Warning: When both application-version-string and application-version are provided, only the string will be used.')
    else:
        application_version_internal = application_version

    if application is not None:
        if not os.path.isfile(application):
            raise click.FileError(application, hint="Application file not found")
        if application_version_internal is None:
            raise click.UsageError('--application-version or --application-version-string'
                                   ' required with application image.')

    if (no_backup is not None) and (backup_address is not None):
        raise click.BadParameter("Bootloader DFU settings backup page cannot be specified if backup is disabled.", param_hint='backup_address')

    if no_backup is None:
        no_backup = False

    if no_backup is False:
        display_settings_backup_warning()

    if (start_address is not None) and (backup_address is None):
        click.echo("WARNING: Using default offset in order to calculate bootloader settings backup page")

    if bl_settings_version == 1 and (app_boot_validation or sd_boot_validation):
        raise click.BadParameter("Bootloader settings version 1 does not support boot validation.", param_hint='bl_settings_version')

    # load signing key (if needed) only once
    if 'VALIDATE_ECDSA_P256_SHA256' in (app_boot_validation, sd_boot_validation):
        if not os.path.isfile(key_file):
            raise click.UsageError("Key file must be given when 'VALIDATE_ECDSA_P256_SHA256' boot validation is used")
        signer = Signing()
        default_key = signer.load_key(key_file)
        if default_key:
            display_sec_warning()
    else:
        signer = None

    if app_boot_validation and not application:
        raise click.UsageError("--application hex file must be set when using --app_boot_validation")

    if sd_boot_validation and not softdevice:
        raise click.UsageError("--softdevice hex file must be set when using --sd_boot_validation")

    # Default boot validation cases
    if app_boot_validation is None and application is not None and bl_settings_version == 2:
        app_boot_validation = DEFAULT_BOOT_VALIDATION
    if sd_boot_validation is None and softdevice is not None and bl_settings_version == 2:
        sd_boot_validation = DEFAULT_BOOT_VALIDATION

    sett = BLDFUSettings()
    sett.generate(arch=family, app_file=application, app_ver=application_version_internal, bl_ver=bootloader_version,
                  bl_sett_ver=bl_settings_version, custom_bl_sett_addr=start_address, no_backup=no_backup,
                  backup_address=backup_address, app_boot_validation_type=app_boot_validation,
                  sd_boot_validation_type=sd_boot_validation, sd_file=softdevice, signer=signer)
    sett.tohexfile(hex_file)

    click.echo("\nGenerated Bootloader DFU settings .hex file and stored it in: {}".format(hex_file))

    click.echo("{0}".format(str(sett)))

@settings.command(short_help='Display the contents of a .hex file with Bootloader DFU settings.')
@click.argument('hex_file', required=True, type=click.Path())

def display(hex_file):

    sett = BLDFUSettings()
    try:
        sett.fromhexfile(hex_file)
    except NordicSemiException as err:
        raise click.UsageError(err)

    click.echo("{0}".format(str(sett)))


@cli.group(short_help='Generate and display private and public keys.')
def keys():
    """
    This set of commands supports creating and displaying a private (signing) key
    as well as displaying the public (verification) key derived from a private key.
    Private keys are stored in PEM format.
    """
    pass

@keys.command(short_help='Generate a private key and store it in a file in PEM format.')
@click.argument('key_file', required=True, type=click.Path())

def generate(key_file):
    signer = Signing()

    if os.path.exists(key_file):
        if not query_func("File found at %s. Do you want to overwrite the file?" % key_file):
            click.echo('Key generation aborted.')
            return

    signer.gen_key(key_file)
    click.echo("Generated private key and stored it in: %s" % key_file)

@keys.command(short_help='Display the private key that is stored in a file in PEM format or a public key derived from it.')
@click.argument('key_file', required=True, type=click.Path())
@click.option('--key',
              help='(pk|sk) Display the public key (pk) or the private key (sk).',
              type=click.Choice(KEY_CHOICE),
              required=True)
@click.option('--format',
              help='(hex|code|pem) Display the key in hexadecimal format (hex), C code (code), or PEM (pem) format.',
              type=click.Choice(KEY_FORMAT),
              required=True)
@click.option('--out_file',
              help='If provided, save the output in file out_file.',
              type=click.STRING)

def display(key_file, key, format, out_file):
    signer = Signing()

    if not os.path.isfile(key_file):
        raise NordicSemiException("File not found: %s" % key_file)

    default_key = signer.load_key(key_file)
    if default_key:
        display_sec_warning()

    if format == "dbgcode":
        format = "code"
        dbg = True
    else:
        dbg = False

    if format == "code" and key == "sk":
        raise click.UsageError("Displaying the private key as code is not available.")

    if key == "pk":
        kstr = signer.get_vk(format, dbg)
    elif key == "sk":
        kstr = "\nWARNING: Security risk! Do not share the private key.\n\n"
        kstr = kstr + signer.get_sk(format, dbg)

    if not out_file:
        click.echo(kstr)
    else:
        with open(out_file, "w") as kfile:
            kfile.write(kstr)


@cli.group(short_help='Display or generate a DFU package (zip file).')
def pkg():
    """
    This set of commands supports Nordic DFU package generation.
    """
    pass


@pkg.command(short_help='Display the contents of a .zip package file.')
@click.argument('zip_file', required=True, type=click.Path())

def display(zip_file):

    package = Package()
    package.parse_package(zip_file, preserve_work_dir=True)

    click.echo("{0}".format(str(package)))

global_bar = None
def update_progress(progress=0):
    if global_bar:
        global_bar.update(progress)

@cli.group(short_help='Perform a Device Firmware Update over serial, BLE transport given a DFU package (zip file).')
def dfu():
    """
    This set of commands supports Device Firmware Upgrade procedures over both BLE and serial transports.
    """
    pass

def do_serial(package, port, connect_delay, flow_control, packet_receipt_notification, baud_rate, serial_number, ping,
              timeout):

    if flow_control is None:
        flow_control = DfuTransportSerial.DEFAULT_FLOW_CONTROL
    if packet_receipt_notification is None:
        packet_receipt_notification = DfuTransportSerial.DEFAULT_PRN
    if baud_rate is None:
        baud_rate = DfuTransportSerial.DEFAULT_BAUD_RATE
    if ping is None:
        ping = False
    if port is None:
        device_lister = DeviceLister()
        device = device_lister.get_device(serial_number=serial_number)
        if device is None:
            raise NordicSemiException("A device with serial number %s is not connected." % serial_number)
        port = device.get_first_available_com_port()
        logger.info("Resolved serial number {} to port {}".format(serial_number, port))

    if timeout is None:
        timeout = DfuTransportSerial.DEFAULT_TIMEOUT

    logger.info("Using board at serial port: {}".format(port))
    serial_backend = DfuTransportSerial(com_port=str(port), baud_rate=baud_rate,
                                        flow_control=flow_control, prn=packet_receipt_notification, do_ping=ping,
                                        timeout=timeout)
    serial_backend.register_events_callback(DfuEvent.PROGRESS_EVENT, update_progress)
    dfu = Dfu(zip_file_path = package, dfu_transport = serial_backend, connect_delay = connect_delay)

    if logger.getEffectiveLevel() > logging.INFO:
        with click.progressbar(length=dfu.dfu_get_total_size()) as bar:
            global global_bar
            global_bar = bar
            dfu.dfu_send_images()
    else:
        dfu.dfu_send_images()

    click.echo("Device programmed.")

@dfu.command(short_help='Update the firmware on a device over a USB serial connection. The DFU '
                        'target must be a chip with USB pins (i.e. nRF52840) and provide a USB ACM '
                        'CDC serial interface.')
@click.option('-pkg', '--package',
              help='Filename of the DFU package.',
              type=click.Path(exists=True, resolve_path=True, file_okay=True, dir_okay=False),
              required=True)
@click.option('-p', '--port',
              help='Serial port address to which the device is connected. (e.g. COM1 in windows systems, /dev/ttyACM0 in linux/mac)',
              type=click.STRING,
              cls = OptionRequiredIf)
@click.option('-cd', '--connect-delay',
              help='Delay in seconds before each connection to the target device during DFU. Default is 3.',
              type=click.INT,
              required=False)
@click.option('-fc', '--flow-control',
              help='To enable flow control set this flag to 1',
              type=click.BOOL,
              required=False)
@click.option('-prn', '--packet-receipt-notification',
              help='Set the packet receipt notification value',
              type=click.INT,
              required=False)
@click.option('-b', '--baud-rate',
              help='Set the baud rate',
              type=click.INT,
              required=False)
@click.option('-snr', '--serial-number',
              help='Serial number of the device. Ignored if --port is set.',
              type=click.STRING,
              required=False)
@click.option('-t', '--timeout',
              help='Set the timeout in seconds for board to respond (default: 30 seconds)',
              type=click.INT,
              required=False)
def usb_serial(package, port, connect_delay, flow_control, packet_receipt_notification, baud_rate, serial_number,
               timeout):
    """Perform a Device Firmware Update on a device with a bootloader that supports USB serial DFU."""
    do_serial(package, port, connect_delay, flow_control, packet_receipt_notification, baud_rate, serial_number, False,
              timeout)


@dfu.command(short_help="Update the firmware on a device over a UART serial connection. The DFU target must be a chip using digital I/O pins as an UART.")
@click.option('-pkg', '--package',
              help='Filename of the DFU package.',
              type=click.Path(exists=True, resolve_path=True, file_okay=True, dir_okay=False),
              required=True)
@click.option('-p', '--port',
              help='Serial port address to which the device is connected. (e.g. COM1 in windows systems, /dev/ttyACM0 in linux/mac)',
              type=click.STRING,
              cls = OptionRequiredIf)
@click.option('-cd', '--connect-delay',
              help='Delay in seconds before each connection to the target device during DFU. Default is 3.',
              type=click.INT,
              required=False)
@click.option('-fc', '--flow-control',
              help='To enable flow control set this flag to 1',
              type=click.BOOL,
              required=False)
@click.option('-prn', '--packet-receipt-notification',
              help='Set the packet receipt notification value',
              type=click.INT,
              required=False)
@click.option('-b', '--baud-rate',
              help='Set the baud rate',
              type=click.INT,
              required=False)
@click.option('-snr', '--serial-number',
              help='Serial number of the device. Ignored if --port is set.',
              type=click.STRING,
              required=False)
@click.option('-t', '--timeout',
              help='Set the timeout in seconds for board to respond (default: 30 seconds)',
              type=click.INT,
              required=False)
def serial(package, port, connect_delay, flow_control, packet_receipt_notification, baud_rate, serial_number,
           timeout):
    """Perform a Device Firmware Update on a device with a bootloader that supports UART serial DFU."""

    do_serial(package, port, connect_delay, flow_control, packet_receipt_notification, baud_rate, serial_number, True,
              timeout)


def enumerate_ports():
    device_lister = DeviceLister()
    descs = device_lister.enumerate()
    if len(descs) == 0:
        raise click.UsageError("\nNo boards found.")

    click.echo('Please select connectivity serial port:')
    for i, choice in enumerate(descs):
        click.echo('\t{} : {} - {}'.format(
                                        i,
                                        choice.get_first_available_com_port(),
                                        choice.serial_number))

    index = click.prompt('Enter your choice: ',
                         type=click.IntRange(0, len(descs)))
    device = descs[index]
    is_jlink = device.vendor_id == "1366"
    return device.get_first_available_com_port(), is_jlink


def get_port_by_snr(snr):
    device_lister = DeviceLister()
    device = device_lister.get_device(serial_number=snr)
    if not device:
        raise NordicSemiException('Board not found')
    is_jlink = device.vendor_id == "1366"
    return device.get_first_available_com_port(), is_jlink


def port_is_jlink(port):
    device_lister = DeviceLister()
    device = device_lister.get_device(com=port)
    if not device:
        raise NordicSemiException('Board not found')
    return device.vendor_id == "1366"


@dfu.command(short_help="Update the firmware on a device over a BLE connection.")
@click.option('-pkg', '--package',
              help='Filename of the DFU package.',
              type=click.Path(exists=True, resolve_path=True, file_okay=True, dir_okay=False),
              required=True)
@click.option('-ic', '--conn-ic-id',
              help='Connectivity IC family: NRF51 or NRF52',
              type=click.Choice(['NRF51', 'NRF52']),
              required=True)
@click.option('-p', '--port',
              help='Serial port COM port to which the connectivity IC is connected.',
              type=click.STRING)
@click.option('-cd', '--connect-delay',
              help='Delay in seconds before each connection to the target device during DFU. Default is 3.',
              type=click.INT,
              required=False)
@click.option('-n', '--name',
              help='Device name.',
              type=click.STRING)
@click.option('-a', '--address',
              help='BLE address of the DFU target device.',
              type=click.STRING)
@click.option('-snr', '--jlink_snr',
              help='Jlink serial number for the connectivity IC.',
              type=click.STRING)
@click.option('-f', '--flash_connectivity',
              help='Flash connectivity firmware automatically. Default: disabled.',
              type=click.BOOL,
              is_flag=True)
@click.option('-mtu', '--att-mtu',
              help='ATT MTU. Maximum ATT packet size for BLE transfers. '
                   'Accepted values in range [23, 247]. Default is 247. '
                   'Note: Failing DFU transmissions can in some cases be solved by setting a '
                   'lower mtu.',
              type=click.IntRange(23, 247, clamp=True),
              default=247)
def ble(package, conn_ic_id, port, connect_delay, name, address, jlink_snr, flash_connectivity, att_mtu):
    """
    Perform a Device Firmware Update on a device with a bootloader that supports BLE DFU.
    This requires a second nRF device, connected to this computer, with connectivity firmware
    loaded. The connectivity device will perform the DFU procedure onto the target device.
    """
    ble_driver_init(conn_ic_id)
    if name is None and address is None:
        name = 'DfuTarg'
        click.echo("No target selected. Default device name: {} is used.".format(name))

    # Remove colons from address in case written in format XX:XX:XX:XX:XX:XX
    if address:
        address = address.replace(':', '')
        if not re.match('^[0-9A-Fa-f]{12}$', address):
            raise click.BadParameter('Must be exactly 6 bytes HEX, '
                                     'e.g. ABCDEF123456 or AB:CD:EF:12:34:56.', param_hint='address')

    if port is None and jlink_snr is not None:
        port, is_jlink = get_port_by_snr(jlink_snr)
    elif port is None:
        port, is_jlink = enumerate_ports()
    else:
        is_jlink = port_is_jlink(port)

    if flash_connectivity:
        if is_jlink:
            flasher = Flasher(serial_port=port, snr=jlink_snr)
            if flasher.fw_check():
                click.echo("Board already flashed with connectivity firmware.")
            else:
                click.echo("Flashing connectivity firmware...")
                flasher.fw_flash()
                click.echo("Connectivity firmware flashed.")
            flasher.reset()
            time.sleep(1)
        else:
            click.echo("Flashing connectivity firmware...")
            serial_backend = DfuTransportSerial(com_port=str(port))
            serial_backend.register_events_callback(DfuEvent.PROGRESS_EVENT,
                                                    update_progress)
            connectivity_firmware = os.path.join(
                                        os.path.dirname(config.__file__),
                                        "hex",
                                        "sd_api_v5",
                                        "connectivity_4.1.4_usb_with_s132_5.1.0_dfu_pkg.zip"
                                    )
            dfu = Dfu(zip_file_path=connectivity_firmware,
                      dfu_transport=serial_backend,
                      connect_delay=connect_delay)
            dfu.dfu_send_images()
            click.echo("Connectivity firmware flashed.")

    logger.info("Using connectivity board at serial port: {}".format(port))
    ble_backend = DfuTransportBle(serial_port=str(port),
                                  att_mtu=att_mtu,
                                  target_device_name=str(name),
                                  target_device_addr=str(address))
    ble_backend.register_events_callback(DfuEvent.PROGRESS_EVENT, update_progress)
    dfu = Dfu(zip_file_path=package, dfu_transport=ble_backend, connect_delay=connect_delay)

    if logger.getEffectiveLevel() > logging.INFO:
        with click.progressbar(length=dfu.dfu_get_total_size()) as bar:
            global global_bar
            global_bar = bar
            dfu.dfu_send_images()
    else:
        dfu.dfu_send_images()

    click.echo("Device programmed.")


def convert_version_string_to_int(s):
    """Convert from semver string "1.2.3", to integer 10203"""
    numbers = s.split(".")
    if len(numbers) != 3:
        raise click.BadParameter("Must be on the format x.y.z", param_hint='application-version-string')
    js = [10000, 100, 1]
    return sum([js[i] * int(numbers[i]) for i in range(3)])


@cli.group()
def restart():
    """
    Utility command to restart dongle application.
    """
    pass

@restart.command(short_help='Restart application on a device over a USB serial connection. The DFU '
                        'target must be a chip with USB pins (i.e. nRF52840) and provide a USB ACM '
                        'CDC serial interface.')
@click.option('-p', '--port',
              help='Serial port address to which the device is connected. (e.g. COM1 in windows systems, /dev/ttyACM0 in linux/mac)',
              type=click.STRING,
              cls=OptionRequiredIf)
@click.option('-cd', '--connect-delay',
              help='Delay in seconds before each connection to the target device during DFU. Default is 3.',
              type=click.INT,
              required=False,
              default=3)
@click.option('-fc', '--flow-control',
              help='To enable flow control set this flag to 1',
              type=click.BOOL,
              required=False)
@click.option('-prn', '--packet-receipt-notification',
              help='Set the packet receipt notification value',
              type=click.INT,
              required=False)
@click.option('-b', '--baud-rate',
              help='Set the baud rate',
              type=click.INT,
              required=False)
@click.option('-snr', '--serial-number',
              help='Serial number of the device. Ignored if --port is set.',
              type=click.STRING,
              required=False)
@click.option('-t', '--timeout',
              help='Set the timeout in seconds for board to respond (default: 30 seconds)',
              type=click.INT,
              required=False)
def usb_serial_restart(port, connect_delay, flow_control, packet_receipt_notification, baud_rate, serial_number,
               timeout):
    """Perform an application restart"""
    if flow_control is None:
        flow_control = DfuTransportSerial.DEFAULT_FLOW_CONTROL
    if packet_receipt_notification is None:
        packet_receipt_notification = DfuTransportSerial.DEFAULT_PRN
    if baud_rate is None:
        baud_rate = DfuTransportSerial.DEFAULT_BAUD_RATE
    if port is None:
        device_lister = DeviceLister()
        device = device_lister.get_device(serial_number=serial_number)
        if device is None:
            raise NordicSemiException("A device with serial number %s is not connected." % serial_number)
        port = device.get_first_available_com_port()
        logger.info("Resolved serial number {} to port {}".format(serial_number, port))

    if timeout is None:
        timeout = DfuTransportSerial.DEFAULT_TIMEOUT

    logger.info("Using board at serial port: {}".format(port))
    serial_backend = DfuTransportSerial(com_port=str(port), baud_rate=baud_rate,
                                        flow_control=flow_control, prn=packet_receipt_notification, do_ping=False,
                                        timeout=timeout, serial_number=serial_number)
    Dfu.restart(serial_backend, connect_delay)
    click.echo("Device restarted")


def _pretty_help_option(text: str):
    formatted_lines = []
    for line in text.split("\n"):
        formatted_lines.append(line + " " * 100)
    return "\n".join(formatted_lines)


if __name__ == '__main__':
    cli()
