/**
 * Detections v2 documents: the batched lookup the case summary uses and the
 * QL search behind sophos_fusion_search_detections. `caseEvidence` returns
 * IDs only, so the summary resolves them here in one call.
 *
 * Operation names use the `detection*` form. The older `alertsService*`
 * aliases behave identically and are not used. Response fields still say
 * `alerts`; read them as detections. Schema: schemas/fusion/detections-v2.graphql.
 *
 * The argument on detectionRetrieveById really is spelled `iDs`. On Alert2
 * the top-level field is `priority`, not `severity`; the 0 to 1 severity
 * lives under `metadata`, and its timestamps are `{ seconds, nanos }` objects.
 */

const DETECTION_FIELDS = `
        id
        status
        resolution_reason
        attack_technique_ids
        sensor_types
        tags
        metadata {
          title
          description
          severity
          confidence
          origin
          created_at { seconds nanos }
          first_seen_at { seconds nanos }
          creator { detector { detector_id detector_name } }
        }
        enrichment_details {
          mitre_attack_info { technique_id technique tactics }
        }
        source_entities { display_name subtype identifiers }
        target_entities { display_name subtype identifiers }
        event_ids { id }`;

export const DETECTIONS_BY_ID = `query FusionDetectionsById($in: GetByIDRequestInput!) {
  detectionRetrieveById(in: $in) {
    alerts {
      total_results
      list {${DETECTION_FIELDS}
      }
    }
  }
}`;

/**
 * The general search. detectionsV2 is not a search (it demands
 * processCorrelationID and lineageID); this is the one that takes QL, for
 * example "from alert severity >= 0.1 EARLIEST=-90d" (live tenant, 22/09/2026).
 */
export const DETECTION_SEARCH = `query FusionDetectionSearch($in: SearchRequestInput!) {
  detectionSearch(in: $in) {
    status
    reason
    search_id
    alerts {
      total_results
      next_offset
      list {${DETECTION_FIELDS}
      }
    }
  }
}`;
