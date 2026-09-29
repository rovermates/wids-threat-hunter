"""Portable header/relationship features: no device identities or capture clocks."""
import numpy as np
import pandas as pd


HEADER_FIELDS = {'to_ds': 'wlan.fc.tods', 'from_ds': 'wlan.fc.fromds',
                 'power_management': 'wlan.fc.pwrmgt', 'more_fragments': 'wlan.fc.frag',
                 'more_data': 'wlan.fc.moredata', 'duration_us': 'wlan.duration'}
RELATIONS = ['source_is_bssid', 'destination_is_bssid', 'destination_multicast', 'ssid_present']
DETECTION_FEATURES = list(HEADER_FIELDS) + RELATIONS


def detection_features(raw):
    output = pd.DataFrame(index=raw.index)
    for name, source in HEADER_FIELDS.items():
        if source not in raw and name in {'to_ds', 'from_ds'} and 'wlan.fc.ds' in raw:
            def bit(value):
                if pd.isna(value) or value in {'', '?'}:
                    return np.nan
                number = int(str(value), 16) if str(value).startswith('0x') else int(value)
                return float(bool(number & (1 if name == 'to_ds' else 2)))
            output[name] = raw['wlan.fc.ds'].map(bit)
            continue
        if source not in raw:
            output[name] = np.nan
            continue
        values = raw[source].astype('string').str.split(',').str[0].replace({'?': pd.NA, '': pd.NA, '<MISSING>': pd.NA,
                                                                         'True': '1', 'False': '0'})
        output[name] = pd.to_numeric(values, errors='raise').astype('float64')
    normalized = {}
    for name in ['source_mac', 'destination_mac', 'bssid']:
        values = raw[name].astype('string').str.lower()
        normalized[name] = values.where(values.str.fullmatch(r'[0-9a-f]{2}(?::[0-9a-f]{2}){5}', na=False))
    bssid = normalized['bssid']
    for name in ['source', 'destination']:
        address = normalized[name + '_mac']
        valid = address.notna() & bssid.notna()
        output[name + '_is_bssid'] = address.eq(bssid).astype('Float64').where(valid).astype('float64')
    destination = normalized['destination_mac']
    output['destination_multicast'] = destination.str.match(r'^[0-9a-f][13579bdf]:').astype('Float64').astype('float64')
    output['ssid_present'] = (raw['ssid'].notna() & raw['ssid'].ne('')).astype('float64')
    return output
