package io.xlogistx.shared.util;

public enum XXStatus {
  CANCELLED,  // Transaction refunded
  COMPLETED, // Delivered
  EXCEPTION, // Delivery exception
  FAILED,   // Order failed
  PENDING,  // Order pending (received)
  PROCESSING, // Delivery in progress
  NOT_AVAILABLE
}