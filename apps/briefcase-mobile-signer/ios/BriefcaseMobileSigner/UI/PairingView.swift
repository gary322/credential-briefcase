import SwiftUI

struct PairingView: View {
    @EnvironmentObject private var model: SignerModel
    @State private var showScanner = false

    var body: some View {
        Form {
            Section("Daemon") {
                TextField("Base URL (e.g. http://192.168.1.10:8787)", text: $model.baseURL)
                    .textInputAutocapitalization(.never)
                    .keyboardType(.URL)
                    .autocorrectionDisabled()

                TextField("Device name (optional)", text: $model.deviceName)
            }

            Section("Pairing") {
                TextField("Pairing ID (UUID)", text: $model.pairingId)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                SecureField("Pairing code (base64url)", text: $model.pairingCode)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()

                Button("Scan QR code") { showScanner = true }
                Button(model.isBusy ? "Pairing..." : "Pair") {
                    Task { await model.pair() }
                }
                .disabled(model.isBusy)
            }

            if let msg = model.statusMessage, !msg.isEmpty {
                Section("Status") {
                    Text(msg)
                        .font(.footnote)
                }
            }
        }
        .navigationTitle("Pair Signer")
        .sheet(isPresented: $showScanner) {
            QRScannerView { s in
                showScanner = false
                guard let payload = PairingPayloadParser.parse(s) else {
                    model.statusMessage = "Unrecognized QR payload"
                    return
                }
                model.applyPairingPayload(payload)
            }
        }
    }
}

