"use client";

import { useState, useEffect } from "react";
import { apiGet } from "../../../lib/api";

interface MerchantInfo {
  name: string;
  did: string;
  spiffe_id: string | null;
  credential_count: number;
  transaction_count: number;
  total_volume: number;
  currency: string;
  verified: boolean;
  categories: string[];
  credential_types: string[];
}

interface MerchantTransaction {
  cart_jti: string;
  amount: number;
  currency: string;
  created_at: string;
}

interface MerchantDetail {
  merchant: MerchantInfo;
  transactions: MerchantTransaction[];
}

export function MarketplaceTab() {
  const [merchants, setMerchants] = useState<MerchantInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [detail, setDetail] = useState<MerchantDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  useEffect(() => {
    apiGet<MerchantInfo[]>("/v1/marketplace/merchants")
      .then(setMerchants)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoading(false));
  }, []);

  async function handleSelectMerchant(did: string) {
    if (selected === did) {
      setSelected(null);
      setDetail(null);
      return;
    }
    setSelected(did);
    setDetailLoading(true);
    setDetail(null);
    try {
      const d = await apiGet<MerchantDetail>(`/v1/marketplace/merchants/${encodeURIComponent(did)}/transactions`);
      setDetail(d);
    } catch (e) {
      // ignore detail error
    } finally {
      setDetailLoading(false);
    }
  }

  const totalVolume = merchants.reduce((s, m) => s + m.total_volume, 0);
  const verifiedCount = merchants.filter((m) => m.verified).length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-gradient-to-r from-emerald-600 to-teal-600 rounded-2xl p-6 text-white">
        <div className="flex items-start gap-4">
          <div className="w-12 h-12 bg-white/20 rounded-xl flex items-center justify-center text-2xl flex-shrink-0">🏪</div>
          <div>
            <h2 className="text-lg font-bold">Agent Marketplace</h2>
            <p className="text-emerald-100 text-sm mt-1">
              Verified merchant agents with W3C MerchantCredentials and real transaction history.
              Every transaction is backed by a cryptographic AP2 mandate.
            </p>
          </div>
        </div>
      </div>

      {loading && (
        <div className="py-12 text-center text-gray-400">
          <div className="w-6 h-6 border-2 border-emerald-400 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
          <p className="text-sm">Loading marketplace...</p>
        </div>
      )}

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-xl p-4 text-sm text-red-700">
          <p className="font-semibold">Failed to load marketplace</p>
          <p className="font-mono text-xs mt-1">{error}</p>
        </div>
      )}

      {!loading && !error && merchants.length === 0 && (
        <div className="bg-blue-50 border border-blue-200 rounded-2xl p-6 text-center">
          <p className="text-2xl mb-2">🌱</p>
          <p className="text-sm font-semibold text-blue-800">No merchant agents yet</p>
          <p className="text-xs text-blue-600 mt-1">
            Click <strong>"Load Demo Data"</strong> in the System State bar above to seed verified merchant agents with transaction histories.
          </p>
        </div>
      )}

      {!loading && merchants.length > 0 && (
        <>
          {/* Summary */}
          <div className="grid grid-cols-3 gap-4">
            <div className="bg-white border border-gray-200 rounded-2xl p-5 text-center">
              <p className="text-4xl font-black text-gray-800">{merchants.length}</p>
              <p className="text-sm text-gray-600 mt-1">Registered merchants</p>
            </div>
            <div className="bg-emerald-50 rounded-2xl p-5 text-center">
              <p className="text-4xl font-black text-emerald-600">{verifiedCount}</p>
              <p className="text-sm text-gray-600 mt-1">W3C credential verified</p>
            </div>
            <div className="bg-white border border-gray-200 rounded-2xl p-5 text-center">
              <p className="text-4xl font-black text-indigo-600">
                ${totalVolume.toLocaleString("en-US", { maximumFractionDigits: 0 })}
              </p>
              <p className="text-sm text-gray-600 mt-1">Total volume (USD)</p>
            </div>
          </div>

          {/* Marketplace */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {merchants.map((merchant) => {
              const isSelected = selected === merchant.did;
              return (
                <div key={merchant.did}>
                  <button
                    onClick={() => handleSelectMerchant(merchant.did)}
                    className={`w-full text-left p-5 rounded-2xl border-2 transition-all ${
                      isSelected
                        ? "border-emerald-400 bg-emerald-50 shadow-md"
                        : "border-gray-200 bg-white hover:border-gray-300 hover:shadow-sm"
                    }`}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-bold text-gray-800">{merchant.name}</span>
                          {merchant.verified && (
                            <span className="text-xs bg-emerald-100 text-emerald-700 px-2 py-0.5 rounded-full font-medium">Verified ✓</span>
                          )}
                        </div>
                        {merchant.categories.length > 0 && (
                          <div className="flex gap-1 flex-wrap mt-1">
                            {merchant.categories.map((cat) => (
                              <span key={cat} className="text-xs bg-gray-100 text-gray-600 px-2 py-0.5 rounded">{cat}</span>
                            ))}
                          </div>
                        )}
                        <p className="text-xs font-mono text-gray-400 mt-1.5 truncate">{merchant.did}</p>
                      </div>
                    </div>
                    <div className="grid grid-cols-3 gap-2 mt-3">
                      {[
                        { label: "Transactions", value: merchant.transaction_count },
                        { label: "Volume", value: `$${merchant.total_volume.toLocaleString("en-US", { maximumFractionDigits: 0 })}` },
                        { label: "Credentials", value: merchant.credential_count },
                      ].map((stat) => (
                        <div key={stat.label} className="text-center">
                          <p className="text-sm font-bold text-gray-800">{stat.value}</p>
                          <p className="text-xs text-gray-500">{stat.label}</p>
                        </div>
                      ))}
                    </div>
                  </button>

                  {/* Transaction detail */}
                  {isSelected && (
                    <div className="mt-2 bg-white border border-gray-200 rounded-2xl overflow-hidden">
                      {detailLoading && (
                        <div className="p-4 text-center text-gray-400 text-sm">Loading transactions...</div>
                      )}
                      {detail && !detailLoading && (
                        <>
                          <div className="px-4 py-3 border-b border-gray-100">
                            <p className="text-xs font-semibold text-gray-600">
                              Transaction history — {detail.transactions.length} AP2 mandate verifications
                            </p>
                          </div>
                          {detail.transactions.length === 0 ? (
                            <div className="p-4 text-center text-gray-400 text-sm">No transactions yet.</div>
                          ) : (
                            <div className="divide-y divide-gray-50 max-h-64 overflow-y-auto">
                              {detail.transactions.map((tx) => (
                                <div key={tx.cart_jti} className="px-4 py-3 flex items-center justify-between">
                                  <div>
                                    <p className="text-xs font-mono text-gray-500 truncate max-w-48">{tx.cart_jti.slice(-12)}…</p>
                                    <p className="text-xs text-gray-400">{tx.created_at.slice(0, 16)}</p>
                                  </div>
                                  <span className="text-sm font-bold text-gray-800">
                                    ${tx.amount.toLocaleString("en-US", { minimumFractionDigits: 2 })}
                                  </span>
                                </div>
                              ))}
                            </div>
                          )}
                          <div className="p-3 bg-gray-50 border-t border-gray-100">
                            <p className="text-xs text-gray-500">
                              Each row is a fulfilled AP2CartMandate verified by the merchant.
                              The cart_jti is a single-use token — presenting it twice would be blocked.
                            </p>
                          </div>
                        </>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </>
      )}

      {!loading && merchants.length === 0 && !error && (
        <div className="py-12 text-center text-gray-400">
          <p className="text-sm">No merchant agents found. Load demo data first.</p>
        </div>
      )}
    </div>
  );
}
