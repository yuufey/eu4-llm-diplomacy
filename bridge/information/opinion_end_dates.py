"""Export stored finite-duration schedules, distinct from observed expiry/removal."""
from .opinion_modifiers import NativeOpinionModifiersSource
from .engine_dates import project_engine_date
from .sources import _result,_source_info

GAPS=['STORED_SCHEDULE_ONLY','ACTUAL_EXPIRY_AND_REMOVAL_NOT_VERIFIED',
      'NON_FIXED_DURATION_END_TIME_NOT_PREDICTED','CACHE_FRESHNESS_UNVERIFIED',
      'COMPLETE_UI_DATE_VISIBILITY_NOT_VERIFIED']

class NativeOpinionEndDatesSource(NativeOpinionModifiersSource):
    field='end_date'

    def catalog(self):
        topic=super().catalog()[0]
        topic['scope_note']='逻辑FRA参与的双向修正记录；投射现有记录准入，实际日期UI和缓存新鲜度未完全核对。'
        topic['fields']={self.field:{'source':type(self).__name__,'coverage':'partial','complete':False,
            'unit':'game_date','scale':1,'period':'current_stored_schedule',
            'basis':'native_opinion_modifier_stored_duration_schedule',
            'value_origin':'copied_record_date_and_constructor_duration_mode',
            'supported_object_types':['country_pair'],'gaps':list(GAPS),
            'description':'原生具名修正记录保存的计划结束日期；不证明实际失效或移除。'}}
        return [topic]

    def _capture_functions(self):
        from . import opinion_end_dates_capture
        return self._capture or opinion_end_dates_capture.capture, self._validator or opinion_end_dates_capture.validate_capture

    @staticmethod
    def _project_record(row):
        qualified=NativeOpinionModifiersSource._project_record(row)
        if qualified['status']!='known':return qualified
        key=qualified['modifier_id'];mode=row['flags_raw']['26']
        if mode not in (0,1):
            return {'status':'unknown','modifier_id':key,'reason':'OPINION_END_DATE_MODE_UNSUPPORTED'}
        if mode==1:
            return {'status':'not_applicable','modifier_id':key,
                    'reason':'RECORD_USES_NON_FIXED_DURATION_MODE','actual_removal_evaluated':False}
        raw=row['record_date_raw'];calendar=project_engine_date(raw)
        if not 1<=calendar['year_index']<=9999:
            return {'status':'unknown','modifier_id':key,'reason':'OPINION_END_DATE_CALENDAR_RANGE'}
        return {'status':'known','modifier_id':key,'scheduled_end_date_raw':raw,
                'scheduled_end_date':calendar['date'],'calendar':'eu4_fixed_365_day',
                'raw_unit':'eu4_hour_tick','tick_of_day':calendar['tick_of_day'],
                'schedule_state':'stored_unverified','actual_removal_evaluated':False}

    def _project_backend(self,report,other,actor,recipient):
        # The parent's internal unit and schema checks still qualify the same
        # record capture. Only the public projection is a date schedule.
        result=super()._project_backend(report,other,actor,recipient)
        if 'unit' in result:
            result.update(unit='game_date',scale=1,period='current_stored_schedule',
                basis='native_opinion_modifier_stored_duration_schedule',
                value_origin='copied_record_date_and_constructor_duration_mode',gaps=list(GAPS))
        return result

    @staticmethod
    def _result(normalized,context,fields,*,reason=None,unavailable=False,target=None,capture_status='not_attempted'):
        provenance={'adapter':'NativeOpinionEndDatesSource','read_only':True,'native_function_invoked':False,
                    'scope':'selected_country_pair','observer':'FRA','target':target,
                    'capture_status':capture_status,'stored_schedule_only':True,'actual_removal_evaluated':False}
        if reason is not None:provenance['reason']=reason
        source=_source_info('NativeOpinionEndDatesSource',context,complete=False,provenance=provenance)
        source['context_scope']='selected_country_pair'
        if unavailable:source['status']='unavailable'
        return _result(normalized,context,fields,False,source)
