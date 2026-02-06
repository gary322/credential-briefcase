import SwiftUI

struct ApprovalsView: View {
    @EnvironmentObject private var model: SignerModel

    var body: some View {
        List {
            Section("Signer") {
                HStack {
                    Text("Signer ID")
                    Spacer()
                    Text(model.signerId?.uuidString ?? "-")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.trailing)
                }
                HStack {
                    Text("Daemon")
                    Spacer()
                    Text(model.baseURL)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.trailing)
                }
            }

            Section("Approvals") {
                if model.approvals.isEmpty {
                    Text("No pending approvals.")
                        .foregroundStyle(.secondary)
                }

                ForEach(model.approvals) { approval in
                    VStack(alignment: .leading, spacing: 6) {
                        Text(approval.tool_id)
                            .font(.headline)
                        Text(approval.reason)
                            .font(.subheadline)
                            .foregroundStyle(.secondary)

                        Text(approval.summary.prettyPrinted())
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(6)

                        Button(model.isBusy ? "Working..." : "Approve") {
                            Task { await model.approve(approval.id) }
                        }
                        .disabled(model.isBusy)
                    }
                }
            }

            if let msg = model.statusMessage, !msg.isEmpty {
                Section("Status") {
                    Text(msg)
                        .font(.footnote)
                }
            }
        }
        .navigationTitle("Approvals")
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button(model.isBusy ? "Refreshing..." : "Refresh") {
                    Task { await model.refreshApprovals() }
                }
                .disabled(model.isBusy)
            }
            ToolbarItem(placement: .topBarLeading) {
                Button("Unpair") { model.unpair() }
                    .disabled(model.isBusy)
            }
        }
        .task {
            if model.approvals.isEmpty {
                await model.refreshApprovals()
            }
        }
    }
}

