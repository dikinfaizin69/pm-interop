//
//  ProfileSnapshot.swift
//  verbatim extract from privamesh/Core/UserProfileService.swift lines 14-41
//

import Foundation

struct ProfileSnapshot: Codable, Hashable {
    /// The user's own display nickname (NFT nick or auto-generated).
    var nickname: String = ""
    var bio: String = ""
    var activeAvatarSeed: String?
    var nicknames: [String] = []
    var avatars: [SnapAvatar] = []
    var listings: [SnapListing] = []
    /// Sender's PrivaMesh+ membership, learned from stamped messages (cosmetic).
    var isPremium: Bool = false

    struct SnapAvatar: Codable, Hashable {
        let seed: String
        let name: String
        let rarity: String?
    }
    struct SnapListing: Codable, Hashable {
        let kind: String   // "avatar" | "nickname"
        let ref: String
        let name: String
        let price: Double
    }

    /// Price this profile is asking for an item ref (nil if not for sale).
    func price(forRef ref: String) -> Double? {
        listings.first { $0.ref == ref }?.price
    }
}
