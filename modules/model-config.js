// Hybrid decision metadata for DNS Phishing Guard v2.7.5.

const MODEL_CONFIG = Object.freeze({
  version: "hybrid-url-ml-v5-coverage-payment-evidence-2026-08-10",
  method: "context-aware-hybrid-url-ml-v5-with-conditional-payment-evidence",
  isMachineLearningModel: true,
  thresholds: Object.freeze({
    suspicious: 10,
    medium: 30,
    high: 70,
    binaryPhishing: 30
  }),
  training: Object.freeze({
    urlModelVersion: "url-logistic-5.0.0",
    datasetSize: 4000,
    safeCount: 2000,
    maliciousCount: 2000,
    phishingCount: 2000,
    featureCount: 54,
    featureVersion: "url-lexical-v4",
    standardizationClamp: 6,
    splitMethod: "Grouped by registrableDomain: approximately 70% train, 10% calibration, 10% threshold selection and 10% independent test",
    thresholdSelection: "Precision-first with stability preference: precision >= 0.965, FPR <= 0.03, recall >= 0.80 when available",
    selectedProbabilityThreshold: 0.59,
    probabilityCalibration: Object.freeze({
      method: "Platt scaling",
      slope: 1.0116712,
      intercept: 0.0684239
    }),
    independentTest: Object.freeze({
      count: 398,
      tp: 185,
      tn: 199,
      fp: 1,
      fn: 13,
      accuracy: 0.9648241,
      precision: 0.9946237,
      recall: 0.9343434,
      f1: 0.9635417,
      falsePositiveRate: 0.005,
      falseNegativeRate: 0.0656566,
      rocAuc: 0.9910606,
      averagePrecision: 0.9929269,
      brierScore: 0.0271986
    }),
    sourceMix: Object.freeze({
      benignCandidates: 2000,
      benignCounterfactual: 800,
      phishing: 1257,
      malwareDownloads: 743
    }),
    hardNegativeTraining: Object.freeze({ count: 479, weight: 2, effectiveRows: 958 })
  }),
  notes: Object.freeze([
    "URL ML chạy cục bộ và không gửi URL ra máy chủ.",
    "Một phần benign được tạo counterfactual có ghi nhãn rõ để mô phỏng profile, bài viết, sản phẩm, dashboard, OAuth và query tracking hợp lệ.",
    "Ký tự @ trong path không còn bị xem là userinfo; chỉ @ trong authority (username/password) mới là tín hiệu che giấu đích.",
    "localhost, loopback và mạng riêng không dùng RDAP, threat-intel công cộng hoặc URL ML công cộng; giao diện hiển thị Không áp dụng.",
    "ML chỉ là chỉ báo bất thường cấu trúc. Cảnh báo on-page cần bằng chứng độc lập; ML đơn lẻ chỉ cập nhật badge/popup.",
    "Brand mismatch của URL chỉ xét hostname và alias domain chính thức; brand xuất hiện trong path/query không tự tạo cảnh báo.",
    "Train/calibration/threshold/test được tách theo registrable domain để tránh domain leakage.",
    "Model không thay thế blacklist, RDAP, threat intelligence, redirect và phân tích hành vi trang.",
    "Risk chưa xác định được trình bày riêng khỏi score nội bộ; coverage không thay đổi metrics URL ML.",
    "Vùng quảng cáo/widget nghi ngờ được tách khỏi content-semantic scan; external form, redirect và risky download vẫn được đánh giá riêng.",
    "Tín hiệu tích hợp cổng thanh toán chỉ tăng độ phủ bằng chứng cho trang SAFE sạch; không giảm Risk score và bị vô hiệu khi có typosquat, brand mismatch hoặc tín hiệu nguy hiểm độc lập."
  ])
});

export { MODEL_CONFIG };
