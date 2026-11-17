IPXWrapper README
=================

Introduction
------------

IPXWrapper allows using software that needs IPX/SPX support on recent versions
of Windows which no longer support it.

Quick start
-----------

Copy the four included DLL files to the directory containing the program that
needs it and run dplay-setup.exe (only required for DirectPlay games).

Choosing network interfaces
---------------------------

By default, IPXWrapper will operate on all network interfaces in the system,
which may not work correctly if you share more than one network with any other
systems running IPXWrapper.

To instead use a single network interface, change the "Primary interface" to
the interface you want to use. Some software may also require you to select the
interface in question inside it. Disabling all other interfaces may make this
easier.

Using a DOSBox IPX server
-------------------------

You can choose to use a DOSBox IPX server to communicate with other hosts
rather than exchanging packets directly, either to allow play over the Internet
or communication between Windows and DOS games (running under DOSBox).

To enable this, select the "DOSBox UDP encapsulation" option in ipxconfig and
enter the address/port of your DOSBox server.

The DOSBox server can be reached using IPv4 or IPv6, provided the server
supports it. The address may be a host name, an IPv4 address (192.0.2.1) or an
IPv6 address (2001:db8::1, optionally in square brackets).

 * If your computer has both IPv4 and IPv6 addresses, the "IP version" list in
   ipxconfig lets you choose between "Automatic", "IPv4 only" and "IPv6 only".
   
   "Automatic" uses whichever the server can be reached by. If the server name
   resolves to an IPv6 and an IPv4 address, they are tried in the order
   preferred by Windows (usually IPv6 first), moving on to the next one if
   there is no answer within a second.
   
   "IPv4 only" and "IPv6 only" never use the other IP version, even if that
   means the server cannot be reached.

 * If your computer only has one of the two, there is nothing to choose and the
   list just shows which one that is.

 * If the server listens on a different port for IPv6 than for IPv4, enter it
   under "Port for IPv6, if different". Leave the field empty otherwise.

Note: Depending on the implementation the other players may need to use the
same IP version as you or not. It the server passes packets between IPv4 and
IPv6 clients it is not necessary to ensure compatibility.

All of the above only applies to the DOSBox UDP encapsulation. The other
encapsulation types work as before (IPXWrapper UDP encapsulation uses IPv4).

Using the real IPX protocol
---------------------------

If your software needs to send/receive real IPX frames, for example because it
talks to an old piece of equipment that only understands IPX, install WinPcap
and select the "Real IPX encapsulation" option in ipxconfig.

Compatibility
-------------

Software that uses WinSock 1.x and/or DirectPlay (before version 8) is supported.

The following have been reported to work:

 * Alien versus Predator Gold
 * Atomic Bomberman
 * Civilization: Call to Power
 * Call to Power II
 * Carmageddon
 * Carmageddon II
 * Command & Conquer: Red Alert 2
 * Darkstone: Evil Reigns
 * Dark Colony
 * Daytona USA Deluxe/Evolution
 * Delta Force
 * Delta Force 2
 * Diablo
 * Dune 2000
 * Dungeon Keeper
 * Dungeon Keeper 2
 * FIFA: Road to World Cup 98
 * Formula 1 97 / Formula 1 Championship Edition
 * Future Cop LAPD
 * Get Medieval
 * Grand Theft Auto II
 * Hardwar: The Future Is Greedy
 * HyperBlade
 * Heroes of Might and Magic III
 * Ignition
 * Interstate '76
 * Laser Arena
 * Machines: Wired for War
 * MageSlayer
 * Midtown Madness
 * Midtown Madness 2
 * Monster Truck Madness
 * Monster Truck Madness 2
 * Motorhead
 * Motocross Madness
 * Motocross Madness 2
 * Moto Racer
 * Moto Racer 2
 * Need for Speed II - Special Edition
 * Need For Speed III - Hot Pursuit
 * Need for Speed: High Stakes
 * Outlive
 * Rising Lands
 * Rival Realms
 * Sega Rally 2
 * Sega Touring Car Championship
 * Sid Meier's Alpha Centauri
 * Speed Demons
 * StarCraft (including BroodWar)
 * Star Wars Episode I: Racer
 * Star Wars Jedi Knight: Dark Forces II
 * Street Wars: Constructor Underworld/Mob Rule
 * Take No Prisoners
 * Test Drive 5
 * Theme Hospital
 * TOCA 2: Touring Cars
 * Total Annihilation
 * Twisted Metal 2
 * Ultimate Race Pro
 * Virtua Cop
 * Warcraft II
 * War Wind
 * War Wind II: Human Onslaught

License
-------

Copyright (C) 2008-2025 Daniel Collins <solemnwarning@solemnwarning.net>
Read license.txt for licensing terms.
