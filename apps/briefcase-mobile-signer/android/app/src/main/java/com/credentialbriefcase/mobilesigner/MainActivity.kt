package com.credentialbriefcase.mobilesigner

import android.app.Application
import android.content.Context
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Divider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import kotlinx.coroutines.launch
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.time.Instant
import java.util.UUID

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    BriefcaseSignerApp()
                }
            }
        }
    }
}

@Composable
private fun BriefcaseSignerApp(vm: SignerViewModel = viewModel()) {
    if (vm.signerId != null) {
        ApprovalsScreen(vm)
    } else {
        PairingScreen(vm)
    }
}

private class SignerViewModel(app: Application) : AndroidViewModel(app) {
    var baseUrl by mutableStateOf("")
    var pairingId by mutableStateOf("")
    var pairingCode by mutableStateOf("")
    var deviceName by mutableStateOf("Android signer")

    var signerId by mutableStateOf<String?>(null)
    var approvals by mutableStateOf<List<ApprovalRequest>>(emptyList())
    var status by mutableStateOf<String?>(null)
    var busy by mutableStateOf(false)

    private val json = Json { ignoreUnknownKeys = true }
    private val prefs = app.getSharedPreferences("briefcase_signer", Context.MODE_PRIVATE)

    init {
        baseUrl = prefs.getString("base_url", "") ?: ""
        signerId = prefs.getString("signer_id", null)
    }

    fun applyPayload(p: PairingPayload) {
        baseUrl = p.base_url
        pairingId = p.pairing_id
        pairingCode = p.pairing_code
        status = null
    }

    fun unpair() {
        signerId = null
        approvals = emptyList()
        status = null
        prefs.edit().remove("signer_id").apply()
    }

    fun pair() {
        viewModelScope.launch {
            status = null
            busy = true
            try {
                val base = baseUrl.trim()
                val pid = pairingId.trim()
                val code = pairingCode.trim()
                val psk = Base64Url.decode(code) ?: throw IllegalArgumentException("invalid pairing code")
                if (psk.size != 32) throw IllegalArgumentException("pairing code wrong length")

                val kp = KeystoreSigner.loadOrCreateKeyPair()
                val pubSec1 = KeystoreSigner.publicKeySec1Bytes(kp.public as java.security.interfaces.ECPublicKey)

                val noise = NoiseNNpsk0Initiator(psk)
                val msg1 = noise.writeMessage1()

                val client = BriefcasedClient(base)
                val resp = client.completePairing(
                    pairingId = pid,
                    req = SignerPairCompleteRequest(
                        msg1_b64 = Base64Url.encode(msg1),
                        algorithm = "p256",
                        signer_pubkey_b64 = Base64Url.encode(pubSec1),
                        device_name = deviceName.ifBlank { null },
                    )
                )

                val msg2 = Base64Url.decode(resp.msg2_b64) ?: throw IllegalArgumentException("invalid msg2")
                val payload = noise.readMessage2(msg2)

                val ack = json.decodeFromString(PairingAck.serializer(), payload.toString(Charsets.UTF_8))
                signerId = ack.signer_id
                approvals = emptyList()
                pairingCode = ""
                status = "Paired"
                prefs.edit()
                    .putString("base_url", base)
                    .putString("signer_id", ack.signer_id)
                    .apply()
            } catch (e: Exception) {
                status = "Pairing failed: ${e.message ?: e}"
            } finally {
                busy = false
            }
        }
    }

    fun refreshApprovals() {
        val sid = signerId ?: return
        viewModelScope.launch {
            status = null
            busy = true
            try {
                val kp = KeystoreSigner.loadOrCreateKeyPair()
                val req = signedRequest(kp, sid, "list_approvals", null)
                val client = BriefcasedClient(baseUrl.trim())
                approvals = client.listApprovals(req).approvals
            } catch (e: Exception) {
                status = "List failed: ${e.message ?: e}"
            } finally {
                busy = false
            }
        }
    }

    fun approve(id: String) {
        val sid = signerId ?: return
        viewModelScope.launch {
            status = null
            busy = true
            try {
                val kp = KeystoreSigner.loadOrCreateKeyPair()
                val req = signedRequest(kp, sid, "approve", id)
                val client = BriefcasedClient(baseUrl.trim())
                client.approve(id, req)
                refreshApprovals()
            } catch (e: Exception) {
                status = "Approve failed: ${e.message ?: e}"
            } finally {
                busy = false
            }
        }
    }

    private fun signedRequest(kp: java.security.KeyPair, signerId: String, kind: String, approvalId: String?): SignerSignedRequest {
        val ts = Instant.now().toString()
        val nonce = UUID.randomUUID().toString()
        val approvalLine = approvalId ?: "-"
        val msg = "$kind\n$signerId\n$approvalLine\n$ts\n$nonce\n"
        val sig = KeystoreSigner.sign(kp.private, msg.toByteArray(Charsets.UTF_8))
        return SignerSignedRequest(
            signer_id = signerId,
            ts_rfc3339 = ts,
            nonce = nonce,
            sig_b64 = Base64Url.encode(sig)
        )
    }

    @Serializable
    private data class PairingAck(val signer_id: String)
}

@Composable
private fun PairingScreen(vm: SignerViewModel) {
    val scannerLauncher = androidx.activity.compose.rememberLauncherForActivityResult(
        contract = ScanContract()
    ) { result ->
        val contents = result.contents
        if (!contents.isNullOrBlank()) {
            val payload = PairingPayloadParser.parse(contents)
            if (payload != null) {
                vm.applyPayload(payload)
            } else {
                vm.status = "Unrecognized QR payload"
            }
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text("Pair Signer", style = MaterialTheme.typography.headlineMedium)

        OutlinedTextField(
            value = vm.baseUrl,
            onValueChange = { vm.baseUrl = it },
            modifier = Modifier.fillMaxWidth(),
            label = { Text("Base URL") },
            singleLine = true
        )
        OutlinedTextField(
            value = vm.pairingId,
            onValueChange = { vm.pairingId = it },
            modifier = Modifier.fillMaxWidth(),
            label = { Text("Pairing ID (UUID)") },
            singleLine = true
        )
        OutlinedTextField(
            value = vm.pairingCode,
            onValueChange = { vm.pairingCode = it },
            modifier = Modifier.fillMaxWidth(),
            label = { Text("Pairing code (base64url)") },
            singleLine = true
        )
        OutlinedTextField(
            value = vm.deviceName,
            onValueChange = { vm.deviceName = it },
            modifier = Modifier.fillMaxWidth(),
            label = { Text("Device name (optional)") },
            singleLine = true
        )

        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Button(onClick = {
                val opts = ScanOptions()
                    .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                    .setPrompt("Scan pairing QR")
                    .setBeepEnabled(false)
                scannerLauncher.launch(opts)
            }) {
                Text("Scan QR")
            }
            Button(onClick = { vm.pair() }, enabled = !vm.busy) {
                Text(if (vm.busy) "Pairing..." else "Pair")
            }
        }

        if (!vm.status.isNullOrBlank()) {
            Divider()
            Text(vm.status ?: "", fontFamily = FontFamily.Monospace)
        }

        Spacer(modifier = Modifier.height(12.dp))
        Text(
            "Note: for cross-device pairing, run briefcased on TCP and ensure local-network access.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun ApprovalsScreen(vm: SignerViewModel) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text("Approvals", style = MaterialTheme.typography.headlineMedium)

        Text("Signer: ${vm.signerId}", style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
        Text("Daemon: ${vm.baseUrl}", style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)

        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Button(onClick = { vm.refreshApprovals() }, enabled = !vm.busy) {
                Text(if (vm.busy) "Refreshing..." else "Refresh")
            }
            Button(onClick = { vm.unpair() }, enabled = !vm.busy) {
                Text("Unpair")
            }
        }

        if (!vm.status.isNullOrBlank()) {
            Text(vm.status ?: "", fontFamily = FontFamily.Monospace)
        }

        Divider()

        LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            items(vm.approvals) { a ->
                ApprovalCard(a = a, busy = vm.busy, onApprove = { vm.approve(a.id) })
                Divider()
            }
        }
    }
}

@Composable
private fun ApprovalCard(a: ApprovalRequest, busy: Boolean, onApprove: () -> Unit) {
    Column(modifier = Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Text(a.tool_id, style = MaterialTheme.typography.titleMedium)
        Text(a.reason, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(
            a.summary.toString(),
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
            Button(onClick = onApprove, enabled = !busy) {
                Text(if (busy) "..." else "Approve")
            }
        }
    }
}
