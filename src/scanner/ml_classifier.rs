use std::collections::HashMap;
use smartcore::linalg::basic::matrix::DenseMatrix;
use smartcore::ensemble::random_forest_classifier::RandomForestClassifier;
use smartcore::tree::decision_tree_classifier::DecisionTreeClassifier;
use smartcore::neighbors::knn_classifier::KNNClassifier;
use smartcore::svm::svc::SVC;
use smartcore::model_selection::train_test_split;
use smartcore::metrics::accuracy;
use smartcore::preprocessing::StandardScaler;
use ndarray::{Array1, Array2};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceFeatures {
    // Response characteristics
    pub response_length: f64,
    pub response_time_ms: f64,
    pub has_binary_data: f64,
    pub entropy: f64,
    
    // Protocol indicators
    pub has_http_headers: f64,
    pub has_ascii_banner: f64,
    pub starts_with_greeting: f64,
    pub contains_version_string: f64,
    
    // Network behavior
    pub connection_accepted: f64,
    pub connection_reset: f64,
    pub timeout_occurred: f64,
    pub multiple_packets: f64,
    
    // Content analysis
    pub contains_json: f64,
    pub contains_xml: f64,
    pub contains_html: f64,
    pub contains_base64: f64,
    
    // Authentication indicators
    pub auth_challenge: f64,
    pub requires_login: f64,
    pub permission_denied: f64,
    pub invalid_request: f64,
    
    // Timing patterns
    pub quick_response: f64,      // < 100ms
    pub medium_response: f64,     // 100-1000ms
    pub slow_response: f64,       // > 1000ms
    pub response_variance: f64,   // Variance across multiple probes
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceClassification {
    pub service_name: String,
    pub confidence: f64,
    pub confidence_scores: HashMap<String, f64>, // Per-algorithm confidence
    pub feature_importance: HashMap<String, f64>,
    pub reasoning: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingExample {
    pub features: ServiceFeatures,
    pub service_label: String,
    pub target: IpAddr,
    pub port: u16,
    pub timestamp: u64,
}

pub struct MLServiceClassifier {
    // Ensemble of trained models
    random_forest: Option<RandomForestClassifier<f64, String>>,
    svm_classifier: Option<SVC<f64, String>>,
    knn_classifier: Option<KNNClassifier<f64, String>>,
    decision_tree: Option<DecisionTreeClassifier<f64, String>>,
    
    // Feature preprocessing
    scaler: Option<StandardScaler<f64>>,
    
    // Training data and labels  
    training_data: Vec<TrainingExample>,
    service_labels: Vec<String>,
    
    // Model performance metrics
    model_accuracies: HashMap<String, f64>,
    feature_names: Vec<String>,
    
    // Confidence thresholds
    high_confidence_threshold: f64,
    medium_confidence_threshold: f64,
}

impl Default for ServiceFeatures {
    fn default() -> Self {
        ServiceFeatures {
            response_length: 0.0,
            response_time_ms: 0.0,
            has_binary_data: 0.0,
            entropy: 0.0,
            has_http_headers: 0.0,
            has_ascii_banner: 0.0,
            starts_with_greeting: 0.0,
            contains_version_string: 0.0,
            connection_accepted: 0.0,
            connection_reset: 0.0,
            timeout_occurred: 0.0,
            multiple_packets: 0.0,
            contains_json: 0.0,
            contains_xml: 0.0,
            contains_html: 0.0,
            contains_base64: 0.0,
            auth_challenge: 0.0,
            requires_login: 0.0,
            permission_denied: 0.0,
            invalid_request: 0.0,
            quick_response: 0.0,
            medium_response: 0.0,
            slow_response: 0.0,
            response_variance: 0.0,
        }
    }
}

impl ServiceFeatures {
    pub fn to_vector(&self) -> Vec<f64> {
        vec![
            self.response_length,
            self.response_time_ms,
            self.has_binary_data,
            self.entropy,
            self.has_http_headers,
            self.has_ascii_banner,
            self.starts_with_greeting,
            self.contains_version_string,
            self.connection_accepted,
            self.connection_reset,
            self.timeout_occurred,
            self.multiple_packets,
            self.contains_json,
            self.contains_xml,
            self.contains_html,
            self.contains_base64,
            self.auth_challenge,
            self.requires_login,
            self.permission_denied,
            self.invalid_request,
            self.quick_response,
            self.medium_response,
            self.slow_response,
            self.response_variance,
        ]
    }
    
    pub fn feature_names() -> Vec<String> {
        vec![
            "response_length".to_string(),
            "response_time_ms".to_string(),
            "has_binary_data".to_string(),
            "entropy".to_string(),
            "has_http_headers".to_string(),
            "has_ascii_banner".to_string(),
            "starts_with_greeting".to_string(),
            "contains_version_string".to_string(),
            "connection_accepted".to_string(),
            "connection_reset".to_string(),
            "timeout_occurred".to_string(),
            "multiple_packets".to_string(),
            "contains_json".to_string(),
            "contains_xml".to_string(),
            "contains_html".to_string(),
            "contains_base64".to_string(),
            "auth_challenge".to_string(),
            "requires_login".to_string(),
            "permission_denied".to_string(),
            "invalid_request".to_string(),
            "quick_response".to_string(),
            "medium_response".to_string(),
            "slow_response".to_string(),
            "response_variance".to_string(),
        ]
    }
}

impl MLServiceClassifier {
    pub fn new() -> Self {
        Self {
            random_forest: None,
            svm_classifier: None,
            knn_classifier: None,
            decision_tree: None,
            scaler: None,
            training_data: Vec::new(),
            service_labels: Vec::new(),
            model_accuracies: HashMap::new(),
            feature_names: ServiceFeatures::feature_names(),
            high_confidence_threshold: 0.8,
            medium_confidence_threshold: 0.5,
        }
    }
    
    pub fn add_training_example(&mut self, example: TrainingExample) {
        self.training_data.push(example);
        
        // Retrain models periodically
        if self.training_data.len() % 50 == 0 && self.training_data.len() >= 100 {
            println!("🧠 Retraining ML models with {} examples", self.training_data.len());
            if let Err(e) = self.train_models() {
                eprintln!("⚠️ ML model training failed: {}", e);
            }
        }
    }
    
    pub fn train_models(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.training_data.len() < 10 {
            return Ok(()); // Need minimum training data
        }
        
        println!("📊 Preparing training data for ML models...");
        
        // Prepare training data
        let mut features_matrix = Vec::new();
        let mut labels = Vec::new();
        
        for example in &self.training_data {
            features_matrix.push(example.features.to_vector());
            labels.push(example.service_label.clone());
        }
        
        // Convert to DenseMatrix for SmartCore
        let features = DenseMatrix::from_2d_vec(&features_matrix);
        
        // Prepare labels vector - get unique labels
        self.service_labels = labels.clone();
        self.service_labels.sort();
        self.service_labels.dedup();
        
        // Split data for training and validation
        let (x_train, x_test, y_train, y_test) = train_test_split(
            &features, 
            &labels, 
            0.2, // 20% for testing
            true, // shuffle
            Some(42) // random seed
        );
        
        // Train Random Forest
        println!("🌳 Training Random Forest classifier...");
        let rf = RandomForestClassifier::fit(
            &x_train, 
            &y_train, 
            Default::default()
        )?;
        
        let rf_predictions = rf.predict(&x_test)?;
        let rf_accuracy = accuracy(&y_test, &rf_predictions);
        self.model_accuracies.insert("random_forest".to_string(), rf_accuracy);
        self.random_forest = Some(rf);
        
        // Train SVM (if enough data)
        if self.training_data.len() >= 50 {
            println!("🔬 Training SVM classifier...");
            let svm = SVC::fit(&x_train, &y_train, Default::default())?;
            let svm_predictions = svm.predict(&x_test)?;
            let svm_accuracy = accuracy(&y_test, &svm_predictions);
            self.model_accuracies.insert("svm".to_string(), svm_accuracy);
            self.svm_classifier = Some(svm);
        }
        
        // Train KNN
        println!("👥 Training KNN classifier...");
        let knn = KNNClassifier::fit(&x_train, &y_train, Default::default())?;
        let knn_predictions = knn.predict(&x_test)?;
        let knn_accuracy = accuracy(&y_test, &knn_predictions);
        self.model_accuracies.insert("knn".to_string(), knn_accuracy);
        self.knn_classifier = Some(knn);
        
        // Train Decision Tree
        println!("🌲 Training Decision Tree classifier...");
        let dt = DecisionTreeClassifier::fit(&x_train, &y_train, Default::default())?;
        let dt_predictions = dt.predict(&x_test)?;
        let dt_accuracy = accuracy(&y_test, &dt_predictions);
        self.model_accuracies.insert("decision_tree".to_string(), dt_accuracy);
        self.decision_tree = Some(dt);
        
        println!("✅ ML model training complete!");
        println!("   Random Forest accuracy: {:.2}%", rf_accuracy * 100.0);
        if let Some(svm_acc) = self.model_accuracies.get("svm") {
            println!("   SVM accuracy: {:.2}%", svm_acc * 100.0);
        }
        println!("   KNN accuracy: {:.2}%", knn_accuracy * 100.0);
        println!("   Decision Tree accuracy: {:.2}%", dt_accuracy * 100.0);
        
        Ok(())
    }
    
    pub fn classify_service(&self, features: &ServiceFeatures) -> ServiceClassification {
        let mut confidence_scores = HashMap::new();
        let mut predictions = Vec::new();
        let mut reasoning = Vec::new();
        
        let feature_vector = vec![features.to_vector()];
        let feature_matrix = DenseMatrix::from_2d_vec(&feature_vector);
        
        // Get predictions from each trained model
        if let Some(ref rf) = self.random_forest {
            if let Ok(prediction) = rf.predict(&feature_matrix) {
                if let Some(pred) = prediction.first() {
                    predictions.push((pred.clone(), "random_forest"));
                    confidence_scores.insert("random_forest".to_string(), 
                        self.model_accuracies.get("random_forest").unwrap_or(&0.5).clone());
                    reasoning.push(format!("Random Forest predicts: {}", pred));
                }
            }
        }
        
        if let Some(ref svm) = self.svm_classifier {
            if let Ok(prediction) = svm.predict(&feature_matrix) {
                if let Some(pred) = prediction.first() {
                    predictions.push((pred.clone(), "svm"));
                    confidence_scores.insert("svm".to_string(), 
                        self.model_accuracies.get("svm").unwrap_or(&0.5).clone());
                    reasoning.push(format!("SVM predicts: {}", pred));
                }
            }
        }
        
        if let Some(ref knn) = self.knn_classifier {
            if let Ok(prediction) = knn.predict(&feature_matrix) {
                if let Some(pred) = prediction.first() {
                    predictions.push((pred.clone(), "knn"));
                    confidence_scores.insert("knn".to_string(), 
                        self.model_accuracies.get("knn").unwrap_or(&0.5).clone());
                    reasoning.push(format!("KNN predicts: {}", pred));
                }
            }
        }
        
        if let Some(ref dt) = self.decision_tree {
            if let Ok(prediction) = dt.predict(&feature_matrix) {
                if let Some(pred) = prediction.first() {
                    predictions.push((pred.clone(), "decision_tree"));
                    confidence_scores.insert("decision_tree".to_string(), 
                        self.model_accuracies.get("decision_tree").unwrap_or(&0.5).clone());
                    reasoning.push(format!("Decision Tree predicts: {}", pred));
                }
            }
        }
        
        // Ensemble voting - weighted by model accuracy
        let final_prediction = self.ensemble_vote(&predictions);
        let ensemble_confidence = self.calculate_ensemble_confidence(&predictions, &final_prediction);
        
        // Generate feature importance explanation
        let feature_importance = self.analyze_feature_importance(features);
        
        ServiceClassification {
            service_name: final_prediction,
            confidence: ensemble_confidence,
            confidence_scores,
            feature_importance,
            reasoning,
        }
    }
    
    fn ensemble_vote(&self, predictions: &[(String, &str)]) -> String {
        let mut vote_weights = HashMap::new();
        
        for (prediction, model_name) in predictions {
            let weight = self.model_accuracies.get(*model_name).unwrap_or(&0.5);
            *vote_weights.entry(prediction.clone()).or_insert(0.0) += weight;
        }
        
        vote_weights.into_iter()
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap())
            .map(|(service, _)| service)
            .unwrap_or_else(|| "unknown".to_string())
    }
    
    fn calculate_ensemble_confidence(&self, predictions: &[(String, &str)], final_prediction: &str) -> f64 {
        let total_weight: f64 = predictions.iter()
            .map(|(_, model)| self.model_accuracies.get(*model).unwrap_or(&0.5))
            .sum();
            
        let supporting_weight: f64 = predictions.iter()
            .filter(|(pred, _)| pred == final_prediction)
            .map(|(_, model)| self.model_accuracies.get(*model).unwrap_or(&0.5))
            .sum();
            
        if total_weight > 0.0 {
            supporting_weight / total_weight
        } else {
            0.0
        }
    }
    
    fn analyze_feature_importance(&self, features: &ServiceFeatures) -> HashMap<String, f64> {
        let mut importance = HashMap::new();
        let feature_values = features.to_vector();
        
        // Simple heuristic-based feature importance
        for (i, &value) in feature_values.iter().enumerate() {
            if let Some(feature_name) = self.feature_names.get(i) {
                // Higher values generally indicate more importance for binary features
                importance.insert(feature_name.clone(), value.abs());
            }
        }
        
        importance
    }
    
    pub fn get_confidence_level(&self, confidence: f64) -> String {
        if confidence >= self.high_confidence_threshold {
            "High".to_string()
        } else if confidence >= self.medium_confidence_threshold {
            "Medium".to_string()
        } else {
            "Low".to_string()
        }
    }
    
    pub fn is_ready(&self) -> bool {
        self.random_forest.is_some() && self.training_data.len() >= 10
    }
    
    pub fn get_model_stats(&self) -> HashMap<String, f64> {
        self.model_accuracies.clone()
    }
}