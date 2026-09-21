/**
 * Detections v2 documents used by the Cases tools. The case summary resolves a
 * case's detection evidence in one batched call; `caseEvidence` itself returns
 * IDs only. The Detections tool family is a later slice.
 *
 * Operation names use the `detection*` form. The older `alertsService*`
 * aliases behave identically and are not used. Response fields still say
 * `alerts`; read them as detections. Schema: schemas/fusion/detections-v2.graphql.
 *
 * The argument really is spelled `iDs`.
 */

export const DETECTIONS_BY_ID = `query FusionDetectionsById($in: GetByIDRequestInput!) {
  detectionRetrieveById(in: $in) {
    alerts {
      total_results
      list {
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
        event_ids { id }
      }
    }
  }
}`;
