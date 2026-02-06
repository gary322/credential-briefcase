import SwiftUI

struct RootView: View {
    @EnvironmentObject private var model: SignerModel

    var body: some View {
        NavigationStack {
            if model.isPaired {
                ApprovalsView()
            } else {
                PairingView()
            }
        }
    }
}

