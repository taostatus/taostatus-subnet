#!/usr/bin/env python3
"""
Patch installed bittensor-cli for testnet runtime compatibility.

Why this exists:
  - Some testnet runtimes do not expose Swap.AlphaSqrtPrice, while btcli wallet
    overview expects it.
  - Public testnet RPC endpoints can reject broad wallet overview storage scans
    with "Storage work rate limit exceeded". When a netuid filter is supplied,
    overview can fetch only that subnet's metadata and skip registered-netuid
    discovery scans instead of reading all subnets.
  - Some testnet subnets can produce tempo - blocks_since_last_step <= 0 during
    register, which causes SCALE encoding to fail with:
      "Negative integers not supported"

This script patches the installed bittensor_cli package in the active Python
environment. It is intentionally outside MASXAI core code and is safe to rerun.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path


def _package_root() -> Path:
    spec = importlib.util.find_spec("bittensor_cli")
    if spec is None or spec.origin is None:
        raise SystemExit("bittensor_cli is not installed in this Python environment")
    return Path(spec.origin).resolve().parent


def _replace_once(
    path: Path, old: str, new: str, label: str, compatible: tuple[str, ...] = ()
) -> bool:
    text = path.read_text()
    if new in text or any(marker in text for marker in compatible):
        print(f"ok: {label} already patched")
        return False
    if old not in text:
        raise SystemExit(f"could not patch {label}: expected code not found in {path}")
    path.write_text(text.replace(old, new, 1))
    print(f"patched: {label}")
    return True


def patch_alpha_sqrt_price(root: Path) -> bool:
    path = root / "src" / "bittensor" / "subtensor_interface.py"
    changed = False

    old_single = """        current_sqrt_price = await self.query(
            module="Swap",
            storage_function="AlphaSqrtPrice",
            params=[netuid],
            block_hash=block_hash,
        )
"""
    new_single = """        try:
            current_sqrt_price = await self.query(
                module="Swap",
                storage_function="AlphaSqrtPrice",
                params=[netuid],
                block_hash=block_hash,
            )
        except Exception:
            return Balance.from_tao(1.0)
"""
    changed |= _replace_once(path, old_single, new_single, "get_subnet_price fallback")

    old_map = """        query = await self.substrate.query_map(
            module="Swap",
            storage_function="AlphaSqrtPrice",
            page_size=page_size,
            block_hash=block_hash,
            fully_exhaust=True,
        )
"""
    new_map = """        try:
            query = await self.substrate.query_map(
                module="Swap",
                storage_function="AlphaSqrtPrice",
                page_size=page_size,
                block_hash=block_hash,
                fully_exhaust=True,
            )
        except Exception:
            return {}
"""
    changed |= _replace_once(path, old_map, new_map, "get_subnet_prices fallback")
    return changed


def patch_filtered_netuid_discovery(root: Path) -> bool:
    path = root / "src" / "bittensor" / "subtensor_interface.py"
    old = """        netuids_with_registered_hotkeys = [
            item
            for sublist in await asyncio.gather(
                *[
                    self.get_netuids_for_hotkey(
                        get_hotkey_pub_ss58(wallet),
                        block_hash=block_hash,
                    )
                    for wallet in all_hotkeys
                ]
            )
            for item in sublist
        ]

        if not filter_for_netuids:
            all_netuids = netuids_with_registered_hotkeys

        else:
            filtered_netuids = [
                netuid for netuid in all_netuids if netuid in filter_for_netuids
            ]

            registered_hotkeys_filtered = [
                netuid
                for netuid in netuids_with_registered_hotkeys
                if netuid in filter_for_netuids
            ]

            # Combine both filtered lists
            all_netuids = filtered_netuids + registered_hotkeys_filtered

        return list(set(all_netuids))
"""
    new = """        if filter_for_netuids:
            return list(
                set(netuid for netuid in all_netuids if netuid in filter_for_netuids)
            )

        netuids_with_registered_hotkeys = [
            item
            for sublist in await asyncio.gather(
                *[
                    self.get_netuids_for_hotkey(
                        get_hotkey_pub_ss58(wallet),
                        block_hash=block_hash,
                    )
                    for wallet in all_hotkeys
                ]
            )
            for item in sublist
        ]

        return list(set(netuids_with_registered_hotkeys))
"""
    return _replace_once(path, old, new, "filtered netuid discovery shortcut")


def patch_negative_era(root: Path) -> bool:
    path = root / "src" / "bittensor" / "extrinsics" / "registration.py"
    old = """            validity_period = tempo - blocks_since_last_step
            era_ = {
                "period": validity_period,
                "current": current_block,
            }
"""
    new = """            validity_period = tempo - blocks_since_last_step
            if validity_period <= 0:
                validity_period = tempo if tempo and tempo > 0 else 64
            era_ = {
                "period": validity_period,
                "current": current_block,
            }
"""
    compatible = (
        "            validity_period = max(tempo - blocks_since_last_step, 8)\n",
    )
    return _replace_once(path, old, new, "registration era clamp", compatible)


def patch_wallet_overview_netuid_filter(root: Path) -> bool:
    path = root / "src" / "commands" / "wallets.py"
    changed = False

    old_gather = """        (
            (all_hotkeys, total_balance),
            _dynamic_info,
            block,
            all_netuids,
        ) = await asyncio.gather(
            _get_total_balance(
                total_balance, subtensor, wallet, all_wallets, block_hash=block_hash
            ),
            subtensor.all_subnets(block_hash=block_hash),
            subtensor.substrate.get_block_number(block_hash=block_hash),
            subtensor.get_all_subnet_netuids(block_hash=block_hash),
        )
        dynamic_info = {info.netuid: info for info in _dynamic_info}
"""
    new_gather = """        if netuids_filter:
            (
                (all_hotkeys, total_balance),
                block,
            ) = await asyncio.gather(
                _get_total_balance(
                    total_balance, subtensor, wallet, all_wallets, block_hash=block_hash
                ),
                subtensor.substrate.get_block_number(block_hash=block_hash),
            )
            all_netuids = netuids_filter
            dynamic_info = {}
        else:
            (
                (all_hotkeys, total_balance),
                _dynamic_info,
                block,
                all_netuids,
            ) = await asyncio.gather(
                _get_total_balance(
                    total_balance, subtensor, wallet, all_wallets, block_hash=block_hash
                ),
                subtensor.all_subnets(block_hash=block_hash),
                subtensor.substrate.get_block_number(block_hash=block_hash),
                subtensor.get_all_subnet_netuids(block_hash=block_hash),
            )
            dynamic_info = {info.netuid: info for info in _dynamic_info}
"""
    changed |= _replace_once(
        path,
        old_gather,
        new_gather,
        "wallet overview netuid metadata narrowing",
    )

    old_filter = """        netuids = await subtensor.filter_netuids_by_registered_hotkeys(
            all_netuids, netuids_filter, all_hotkeys
        )

        for netuid in netuids:
"""
    new_filter = """        netuids = await subtensor.filter_netuids_by_registered_hotkeys(
            all_netuids, netuids_filter, all_hotkeys, block_hash=block_hash
        )

        if netuids_filter and netuids:
            _dynamic_info = await asyncio.gather(
                *[
                    subtensor.subnet(netuid, block_hash=block_hash)
                    for netuid in netuids
                ]
            )
            dynamic_info = {info.netuid: info for info in _dynamic_info}

        for netuid in netuids:
"""
    changed |= _replace_once(
        path,
        old_filter,
        new_filter,
        "wallet overview filtered subnet metadata",
    )
    return changed


def main() -> None:
    root = _package_root()
    print(f"bittensor_cli: {root}")
    changed = patch_alpha_sqrt_price(root)
    changed |= patch_filtered_netuid_discovery(root)
    changed |= patch_wallet_overview_netuid_filter(root)
    changed |= patch_negative_era(root)
    print("done: patched" if changed else "done: no changes needed")


if __name__ == "__main__":
    main()
