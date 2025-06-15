package reality.auth;

import tigase.db.DataSource;
import tigase.db.beans.DataSourceBean;
import tigase.db.beans.MDPoolBean;
import tigase.kernel.beans.Bean;
import tigase.kernel.beans.selector.ConfigType;
import tigase.kernel.beans.selector.ConfigTypeEnum;
import tigase.stats.ComponentStatisticsProvider;
import tigase.stats.StatisticsList;

@Bean(name = "fake-data-source", active = true)
@ConfigType({ConfigTypeEnum.DefaultMode, ConfigTypeEnum.SessionManagerMode, ConfigTypeEnum.ConnectionManagersMode,
        ConfigTypeEnum.ComponentMode})
public class FakeDataSource extends MDPoolBean<DataSource, DataSourceBean.DataSourceMDConfigBean>
        implements ComponentStatisticsProvider {

    @Override
    protected Class<? extends DataSourceBean.DataSourceMDConfigBean> getConfigClass() {
        return null;
    }

    @Override
    protected void addRepo(String domain, DataSource repo) {

    }

    @Override
    protected DataSource removeRepo(String domain) {
        return null;
    }

    @Override
    protected void setDefault(DataSource repo) {

    }

    @Override
    public Class<?> getDefaultBeanClass() {
        return null;
    }

    @Override
    public void everyHour() {

    }

    @Override
    public void everyMinute() {

    }

    @Override
    public void everySecond() {

    }

    @Override
    public void getStatistics(String compName, StatisticsList list) {

    }
}
