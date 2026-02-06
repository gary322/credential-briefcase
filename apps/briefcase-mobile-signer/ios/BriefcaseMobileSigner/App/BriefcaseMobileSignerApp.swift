import SwiftUI

@main
struct BriefcaseMobileSignerApp: App {
    @StateObject private var model = SignerModel()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(model)
        }
    }
}

