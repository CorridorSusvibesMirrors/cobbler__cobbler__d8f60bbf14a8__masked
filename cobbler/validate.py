"""
Copyright 2014-2015. Jorgen Maas <jorgen.maas@gmail.com>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
02110-1301  USA
"""

import re
import shlex
from urllib.parse import urlparse
from ipaddress import AddressValueError, NetmaskValueError
from typing import Union

import netaddr

from cobbler import enums, utils

RE_HOSTNAME = re.compile(r'^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*$')
RE_URL_GRUB = re.compile(r"^\((?P<protocol>http|tftp),(?P<server>.*)\)/(?P<path>.*)$")
RE_URL = re.compile(r'^[a-zA-Z\d-]{,63}(\.[a-zA-Z\d-]{,63})*$')  # https://stackoverflow.com/a/2894918

# blacklist invalid values to the repo statement in autoinsts
AUTOINSTALL_REPO_BLACKLIST = ['enabled', 'gpgcheck', 'gpgkey']


# FIXME: Allow the <<inherit>> magic string to be parsed correctly.


def hostname(dnsname: str) -> str:
    """
    Validate the DNS name.

    :param dnsname: Hostname or FQDN
    :returns: Hostname or FQDN
    :raises TypeError: If the Hostname/FQDN is not a string or in an invalid format.
    """
    if not isinstance(dnsname, str):
        raise TypeError("Invalid input, dnsname must be a string")
    else:
        dnsname = dnsname.strip()

    if dnsname == "":
        # hostname is not required
        return dnsname

    if not RE_HOSTNAME.match(dnsname):
        raise ValueError("Invalid hostname format (%s)" % dnsname)

    return dnsname


def mac_address(mac: str, for_item=True) -> str:
    """
    Validate as an Ethernet MAC address.

    :param mac: MAC address
    :param for_item: If the check should be performed for an item or not.
    :returns: MAC address
    :raises ValueError: Raised in case ``mac`` has an invalid format.
    :raises TypeError: Raised in case ``mac`` is not a string.
    """
    if not isinstance(mac, str):
        raise TypeError("Invalid input, mac must be a string")
    mac = mac.lower().strip()

    if for_item is True:
        # this value has special meaning for items
        if mac == "random":
            return mac

        # copying system collection will set mac to ""
        # netaddr will fail to validate this mac and throws an exception
        if mac == "":
            return mac

    if not netaddr.valid_mac(mac):
        raise ValueError("Invalid mac address format (%s)" % mac)

    return mac


def ipv4_address(addr: str) -> str:
    """
    Validate an IPv4 address.

    :param addr: IPv4 address
    :returns: IPv4 address
    :raises TypeError: Raised if ``addr`` is not a string.
    :raises AddressValueError: Raised in case ``addr`` is not a valid IPv4 address.
    :raises NetmaskValueError: Raised in case ``addr`` is not a valid IPv4 netmask.
    """
    if not isinstance(addr, str):
        raise TypeError("Invalid input, addr must be a string")
    addr = addr.strip()

    if addr == "":
        return addr

    if not netaddr.valid_ipv4(addr):
        raise AddressValueError("Invalid IPv4 address format (%s)" % addr)

    if netaddr.IPAddress(addr).is_netmask():
        raise NetmaskValueError("Invalid IPv4 host address (%s)" % addr)

    return addr


def ipv4_netmask(addr: str) -> str:
    """
    Validate an IPv4 netmask.

    :param addr: IPv4 netmask
    :returns: IPv4 netmask
    :raises TypeError: Raised if ``addr`` is not a string.
    :raises AddressValueError: Raised in case ``addr`` is not a valid IPv4 address.
    :raises NetmaskValueError: Raised in case ``addr`` is not a valid IPv4 netmask.
    """
    if not isinstance(addr, str):
        raise TypeError("Invalid input, addr must be a string")
    addr = addr.strip()

    if addr == "":
        return addr

    if not netaddr.valid_ipv4(addr):
        raise AddressValueError("Invalid IPv4 address format (%s)" % addr)

    if not netaddr.IPAddress(addr).is_netmask():
        raise NetmaskValueError("Invalid IPv4 netmask (%s)" % addr)

    return addr


def ipv6_address(addr: str) -> str:
    """
    Validate an IPv6 address.

    :param addr: IPv6 address
    :returns: The IPv6 address.
    :raises TypeError: Raised if ``addr`` is not a string.
    :raises AddressValueError: Raised in case ``addr`` is not a valid IPv6 address.
    """
    if not isinstance(addr, str):
        raise TypeError("Invalid input, addr must be a string")
    addr = addr.strip()

    if addr == "":
        return addr

    if not netaddr.valid_ipv6(addr):
        raise AddressValueError("Invalid IPv6 address format (%s)" % addr)

    return addr


def name_servers(nameservers: Union[str, list], for_item: bool = True) -> Union[str, list]:
    """
    Validate nameservers IP addresses, works for IPv4 and IPv6

    :param nameservers: string or list of nameserver addresses
    :param for_item: enable/disable special handling for Item objects
    :return: The list of valid nameservers.
    :raises TypeError: Raised if ``nameservers`` is not a string or list.
    :raises AddressValueError: Raised in case ``nameservers`` is not a valid address.
    """
    if isinstance(nameservers, str):
        nameservers = nameservers.strip()
        if for_item is True:
            # special handling for Items
            if nameservers in [enums.VALUE_INHERITED, ""]:
                return nameservers

        # convert string to a list; do the real validation in the isinstance(list) code block below
        nameservers = shlex.split(nameservers)

    if isinstance(nameservers, list):
        for ns in nameservers:
            ip_version = netaddr.IPAddress(ns).version
            if ip_version == 4:
                ipv4_address(ns)
            elif ip_version == 6:
                ipv6_address(ns)
            else:
                raise AddressValueError("Invalid IP address format")
    else:
        raise TypeError("Invalid input type %s, expected str or list" % type(nameservers))

    return nameservers


def name_servers_search(search: Union[str, list], for_item: bool = True) -> Union[str, list]:
    """
    Validate nameservers search domains.

    :param search: One or more search domains to validate.
    :param for_item: (enable/disable special handling for Item objects)
    :return: The list of valid nameservers.
    :raises TypeError: Raised if ``search`` is not a string or list.
    """
    if isinstance(search, str):
        search = search.strip()
        if for_item is True:
            # special handling for Items
            if search in [enums.VALUE_INHERITED, ""]:
                return search

        # convert string to a list; do the real validation in the isinstance(list) code block below
        search = shlex.split(search)

    if isinstance(search, list):
        for sl in search:
            hostname(sl)
    else:
        raise TypeError("Invalid input type \"%s\", expected str or list" % type(search))

    return search


def validate_breed(breed: str) -> str:
    """
    This is a setter for the operating system breed.

    :param breed: The os-breed which shall be set.
    :raises TypeError: If breed is not a str.
    :raises ValueError: If breed is not a supported breed.
    """
    if not isinstance(breed, str):
        raise TypeError("breed must be of type str")
    if not breed:
        return ""
    # FIXME: The following line will fail if load_signatures() from utils.py was not called!
    valid_breeds = utils.get_valid_breeds()
    breed = breed.lower()
    if breed and breed in valid_breeds:
        return breed
    nicer = ", ".join(valid_breeds)
    raise ValueError("Invalid value for breed (\"%s\"). Must be one of %s, different breeds have different levels of "
                     "support!" % (breed, nicer))


def validate_os_version(os_version: str, breed: str) -> str:
    """
    This is a setter for the operating system version of an object.

    :param os_version: The version which shall be set.
    :param breed: The breed to validate the os_version for.
    """
    # Type checks
    if not isinstance(os_version, str):
        raise TypeError("os_version needs to be of type str")
    if not isinstance(breed, str):
        raise TypeError("breed needs to be of type str")
    # Early bail out if we do a reset
    if not os_version or not breed:
        return ""
    # Check breed again, so access does not fail
    validated_breed = validate_breed(breed)
    if not validated_breed == breed:
        raise ValueError("The breed supplied to the validation function of os_version was not valid.")
    # Now check the os_version
    # FIXME: The following line will fail if load_signatures() from utils.py was not called!
    matched = utils.SIGNATURE_CACHE["breeds"][breed]
    os_version = os_version.lower()
    if os_version not in matched:
        nicer = ", ".join(matched)
        raise ValueError("os_version for breed \"%s\" must be one of %s, given was \"%s\"" % (breed, nicer, os_version))
    return os_version


def validate_arch(arch: Union[str, enums.Archs]) -> enums.Archs:
    """
    This is a validator for system architectures. If the arch is not valid then an exception is raised.

    :param arch: The desired architecture to set for the object.
    :raises TypeError: In case the any type other then str or enums.Archs was supplied.
    :raises ValueError: In case the supplied str could not be converted.
    """
    # Convert an arch which came in as a string
    if isinstance(arch, str):
        try:
            arch = enums.Archs[arch.upper()]
        except KeyError as error:
            raise ValueError("arch choices include: %s" % list(map(str, enums.Archs))) from error
    # Now the arch MUST be from the type for the enum.
    if not isinstance(arch, enums.Archs):
        raise TypeError("arch needs to be of type enums.Archs")
    return arch


def validate_repos(repos: list, api, bypass_check: bool = False):
    """
    This is a setter for the repository.

    :param repos: The repositories to set for the object.
    :param api: The api to find the repos.
    :param bypass_check: If the newly set repos should be checked for existence.
    """
    # allow the magic inherit string to persist
    if repos == enums.VALUE_INHERITED:
        return enums.VALUE_INHERITED

    # store as an array regardless of input type
    if repos is None:
        repos = []
    else:
        # TODO: Don't store the names. Store the internal references.
        repos = utils.input_string_or_list(repos)
    if not bypass_check:
        for r in repos:
            # FIXME: First check this and then set the repos if the bypass check is used.
            if api.repos().find(name=r) is None:
                raise ValueError("repo %s is not defined" % r)
    return repos















