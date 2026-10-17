/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.util

import android.content.Context
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.wireguard.android.R
import com.wireguard.android.model.ObservableTunnel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL

object AccountStatusChecker {
    private const val API_URL = "http://ytlink.ir:8080/check_expire.php?ip="

    suspend fun checkStatus(context: Context, tunnel: ObservableTunnel) {
        val loadingDialog = withContext(Dispatchers.Main) {
            MaterialAlertDialogBuilder(context)
                .setTitle(tunnel.name)
                .setMessage(context.getString(R.string.checking_account_status))
                .setCancelable(false)
                .show()
        }

        try {
            val config = tunnel.getConfigAsync()
            val addresses = config.`interface`.addresses
            val address = addresses.firstOrNull()?.address?.hostAddress

            if (address.isNullOrBlank()) {
                withContext(Dispatchers.Main) {
                    loadingDialog.dismiss()
                    MaterialAlertDialogBuilder(context)
                        .setTitle(tunnel.name)
                        .setMessage(context.getString(R.string.account_status_no_ip))
                        .setPositiveButton(android.R.string.ok, null)
                        .show()
                }
                return
            }

            val result = withContext(Dispatchers.IO) {
                fetchAccountStatus(address)
            }

            withContext(Dispatchers.Main) {
                loadingDialog.dismiss()
                showResultDialog(context, tunnel.name, address, result)
            }
        } catch (e: Throwable) {
            withContext(Dispatchers.Main) {
                loadingDialog.dismiss()
                MaterialAlertDialogBuilder(context)
                    .setTitle(tunnel.name)
                    .setMessage(context.getString(R.string.account_status_error, e.localizedMessage ?: e.message))
                    .setPositiveButton(android.R.string.ok, null)
                    .show()
            }
        }
    }

    private fun fetchAccountStatus(ip: String): AccountStatusResult {
        val url = URL(API_URL + ip)
        val conn = url.openConnection() as HttpURLConnection
        conn.requestMethod = "GET"
        conn.connectTimeout = 8000
        conn.readTimeout = 8000
        conn.setRequestProperty("Accept", "application/json")

        val responseCode = conn.responseCode
        val stream = if (responseCode in 200..299) conn.inputStream else conn.errorStream
        val responseBody = BufferedReader(InputStreamReader(stream ?: conn.inputStream)).use { it.readText() }
        val json = JSONObject(responseBody)

        val status = json.optString("status")
        if (status != "success") {
            val msg = json.optString("message", "User not found")
            return AccountStatusResult(success = false, errorMessage = msg)
        }

        val hasExpiration = json.optBoolean("has_expiration", false)
        val isExpired = json.optBoolean("is_expired", false)
        val isDisabled = json.optBoolean("is_disabled", false)
        val remainingDays = if (json.has("remaining_days") && !json.isNull("remaining_days")) json.optDouble("remaining_days") else null
        val expireDate = json.optString("expire_date", "")
        val lastHandshake = json.optString("last_handshake", "")
        val rxBytes = json.optLong("rx_bytes", 0L)
        val txBytes = json.optLong("tx_bytes", 0L)

        return AccountStatusResult(
            success = true,
            hasExpiration = hasExpiration,
            isExpired = isExpired,
            isDisabled = isDisabled,
            remainingDays = remainingDays,
            expireDate = expireDate,
            lastHandshake = lastHandshake,
            rxBytes = rxBytes,
            txBytes = txBytes
        )
    }

    private fun showResultDialog(context: Context, tunnelName: String, ip: String, result: AccountStatusResult) {
        if (!result.success) {
            MaterialAlertDialogBuilder(context)
                .setTitle(tunnelName)
                .setMessage(result.errorMessage ?: context.getString(R.string.account_status_not_found))
                .setPositiveButton(android.R.string.ok, null)
                .show()
            return
        }

        val message = StringBuilder()
        message.append("IP: ").append(ip).append("\n\n")

        if (result.isExpired) {
            message.append(context.getString(R.string.account_status_expired)).append("\n")
        } else if (result.hasExpiration && result.remainingDays != null) {
            val daysInt = result.remainingDays.toInt()
            if (daysInt <= 0) {
                message.append(context.getString(R.string.account_status_expires_today)).append("\n")
            } else {
                message.append(context.getString(R.string.account_status_remaining_days, daysInt)).append("\n")
            }
        } else if (!result.hasExpiration) {
            message.append(context.getString(R.string.account_status_unlimited)).append("\n")
        }

        if (!result.expireDate.isNullOrBlank()) {
            message.append(context.getString(R.string.account_status_expire_date, result.expireDate)).append("\n")
        }

        if (result.isDisabled) {
            message.append(context.getString(R.string.account_status_disabled_warning)).append("\n")
        }

        if (result.rxBytes > 0 || result.txBytes > 0) {
            val rxFormatted = QuantityFormatter.formatBytes(result.rxBytes)
            val txFormatted = QuantityFormatter.formatBytes(result.txBytes)
            message.append("\n").append(context.getString(R.string.transfer_rx_tx, rxFormatted, txFormatted))
        }

        MaterialAlertDialogBuilder(context)
            .setTitle(context.getString(R.string.account_status_title, tunnelName))
            .setMessage(message.toString())
            .setPositiveButton(android.R.string.ok, null)
            .show()
    }

    data class AccountStatusResult(
        val success: Boolean,
        val errorMessage: String? = null,
        val hasExpiration: Boolean = false,
        val isExpired: Boolean = false,
        val isDisabled: Boolean = false,
        val remainingDays: Double? = null,
        val expireDate: String? = null,
        val lastHandshake: String? = null,
        val rxBytes: Long = 0L,
        val txBytes: Long = 0L
    )
}

