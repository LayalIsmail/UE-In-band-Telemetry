# P4 Code for User Equipment Telemetry in 6G Networks

This repository contains the P4 implementation deployed in User Equipment (UE) to enable real-time telemetry monitoring and latency diagnostics for end-to-end network performance.

## Overview

A dedicated UE In-band Telemetry system has been developed and implemented, leveraging the standard design of INT over UDP. This system includes:

- **Shim Header**: A 4-byte header that indicates the presence of telemetry data.
- **INT Header**: An 8-byte header that follows the shim header and contains information about the stack of metadata that follows it.
- **Metadata Stack**: A stack of metadata headers that follows the INT header.

This standard in-band telemetry structure has been extended to not only monitor standard metadata but also customize the monitoring operation by tracking new key parameters, including:

- **Received Signal Strength Indicator (RSSI)** of the wireless link.
- **Geolocation Information**: GPS longitude, latitude, and altitude.
- **CPU Load**.

The designed UE In-band Telemetry can be activated for specific data flows.
P4 Code for User Equipment Telemetry in 6G Networks 
This repository contains the P4 implementation deployed in User Equipment (UE) to enable real-time telemetry monitoring and latency diagnostics for end-to-end network performance. 

Overview
A dedicated UE In-band Telemetry system has been developed and implemented, leveraging the standard design of INT over UDP. This system includes:

    • Shim Header: A 4-byte header that indicates the presence of telemetry data.
    • INT Header: An 8-byte header that follows the shim header and contains information about the stack of metadata that follows it.
    • Metadata Stack: A stack of metadata headers that follows the INT header.
      
This standard in-band telemetry structure has been extended to not only monitor standard metadata but also customize the monitoring operation by tracking new key parameters, including:

    • Received Signal Strength Indicator (RSSI) of the wireless link.
    • Geolocation Information: GPS longitude, latitude, and altitude.
    • CPU Load.
      
The designed UE In-band Telemetry can be activated for specific data flows
